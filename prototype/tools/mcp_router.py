"""
tools/mcp_router.py — route ALLOW-ed tool calls to a REAL MCP server over stdio.

Plan-A (real-MCP transport validation). The PEP is transport-agnostic: this router
implements the same `execute(call: ToolCall) -> str` contract as ToolRegistry, but
instead of calling an in-process Python function it issues a JSON-RPC `tools/call`
to a real MCP server (default: the official @modelcontextprotocol/server-filesystem)
over stdio. SI/DS labelling, policy evaluation, and audit are unchanged and sit ABOVE
this boundary.

A single persistent ClientSession is kept alive in a background asyncio loop, so the
per-call cost measured in the overhead benchmark (D2) is the real JSON-RPC encode +
IPC + decode cost, NOT a per-call server spawn.

Usage:
    router = McpRouter.start_filesystem(server_root="/abs/sandbox",
                                        pep_workspace_root="/abs/sandbox/workspace",
                                        pep_cwd="/abs/sandbox", pin_version="2025.8.21")
    text = router.execute(ToolCall(tool="filesystem.read_file", args={"path": "workspace/report.txt"}, ...))
    router.close()
"""
from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# Map our canonical dot-tool-names -> (mcp_tool_name, arg-transform).
# The official filesystem server exposes read_text_file / write_file / list_directory.
# We map both legacy and current names defensively (resolved against list_tools at start).
_FS_TOOL_CANDIDATES = {
    "filesystem.read_file":  ["read_text_file", "read_file"],
    "filesystem.write_file": ["write_file"],
    "filesystem.list_dir":   ["list_directory"],
}


@dataclass
class _Resolved:
    mcp_name: str


class McpRouter:
    """Persistent stdio MCP client exposing the registry execute() contract."""

    def __init__(self, server_params: StdioServerParameters):
        self._params = server_params
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._session: Optional[ClientSession] = None
        self._ctx_stdio = None
        self._ctx_session = None
        self._tool_map: dict[str, _Resolved] = {}
        self._available: list[str] = []
        self._ready = threading.Event()
        self._start_err: Optional[BaseException] = None
        self._thread.start()
        self._ready.wait(timeout=60)
        if self._start_err:
            raise self._start_err

    # ---- lifecycle ----
    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect())
        except BaseException as e:  # noqa: BLE001
            self._start_err = e
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()

    async def _connect(self):
        self._ctx_stdio = stdio_client(self._params)
        read, write = await self._ctx_stdio.__aenter__()
        self._ctx_session = ClientSession(read, write)
        self._session = await self._ctx_session.__aenter__()
        await self._session.initialize()
        tools = await self._session.list_tools()
        self._available = [t.name for t in tools.tools]
        # resolve our dot-names against what this server actually offers
        for dot, candidates in _FS_TOOL_CANDIDATES.items():
            for c in candidates:
                if c in self._available:
                    self._tool_map[dot] = _Resolved(mcp_name=c)
                    break

    @classmethod
    def start_filesystem(cls, server_root: str, pep_workspace_root: str,
                         pep_cwd: Optional[str] = None,
                         pin_version: Optional[str] = None) -> "McpRouter":
        """Launch the official filesystem MCP server rooted at server_root.

        pep_workspace_root / pep_cwd: the SAME anchors the PEP uses for R03 path
        normalisation. The router resolves agent paths through the SAME
        normalize_workspace_path function with the SAME anchors the PEP used, so
        the file the MCP server operates on matches the file the PEP evaluated for
        the static path string (this eliminates the bare-path divergence an earlier
        version had). It does NOT remove check-to-execution TOCTOU: the PEP and the
        router resolve independently, so a path whose target changes between the two
        (e.g. a swapped symlink) could still diverge. Stated as a limitation."""
        import os
        root = os.path.abspath(server_root)
        pkg = "@modelcontextprotocol/server-filesystem"
        if pin_version:
            pkg = f"{pkg}@{pin_version}"
        params = StdioServerParameters(
            command="npx", args=["-y", pkg, root], env=None,
        )
        inst = cls(params)
        inst._root = root
        inst._pep_ws = os.path.abspath(pep_workspace_root)
        inst._pep_cwd = os.path.abspath(pep_cwd) if pep_cwd else None
        inst._pinned = pin_version
        return inst

    def _resolve_path(self, p: str) -> str:
        """Resolve an agent path through the PEP's OWN normalisation so the MCP
        server operates on the same file the PEP evaluated for R03. FAIL CLOSED:
        if resolution errors or yields nothing, raise so execute() refuses the
        call rather than falling back to an unvetted raw path (fail-open)."""
        ws = getattr(self, "_pep_ws", None)
        if ws is None:
            raise ValueError("router not bound to a PEP workspace; refusing to execute")
        from pep.path_normalizer import normalize_workspace_path
        np = normalize_workspace_path(p, workspace_root=ws, cwd=self._pep_cwd)
        if getattr(np, "path_normalization_error", None):
            raise ValueError(f"path normalisation failed: {np.path_normalization_error}")
        ab = getattr(np, "normalized_abs", None)
        if not ab:
            raise ValueError("path normalisation produced no canonical path")
        return ab

    # ---- execute (registry contract) ----
    def execute(self, call) -> str:
        """ToolRegistry-compatible: run an ALLOW-ed call over real MCP, return str."""
        resolved = self._tool_map.get(call.tool)
        if resolved is None:
            # tool not served by this MCP server (e.g. send_email in fs-only minimal run)
            return f"[ERROR: tool '{call.tool}' not exposed by MCP server " \
                   f"(available: {', '.join(self._available)})]"
        args = {k: v for k, v in (call.args or {}).items() if not k.startswith("__")}
        try:
            if "path" in args:
                args["path"] = self._resolve_path(args["path"])  # fail-closed
        except Exception as e:  # noqa: BLE001
            return f"[ERROR: refusing MCP call '{call.tool}': path resolution failed ({e})]"
        fut = asyncio.run_coroutine_threadsafe(
            self._call(resolved.mcp_name, args), self._loop
        )
        try:
            return fut.result(timeout=60)
        except Exception as e:  # noqa: BLE001
            return f"[ERROR: MCP call '{call.tool}' raised {type(e).__name__}: {e}]"

    async def _call(self, mcp_name: str, arguments: dict) -> str:
        res = await self._session.call_tool(mcp_name, arguments=arguments)
        # flatten text content blocks
        parts = []
        for block in (res.content or []):
            txt = getattr(block, "text", None)
            if txt is not None:
                parts.append(txt)
        out = "\n".join(parts) if parts else ""
        if getattr(res, "isError", False):
            return f"[ERROR: {out}]"
        return out

    def available_tools(self) -> list[str]:
        return list(self._available)

    def close(self):
        async def _shutdown():
            try:
                if self._ctx_session is not None:
                    await self._ctx_session.__aexit__(None, None, None)
            finally:
                if self._ctx_stdio is not None:
                    await self._ctx_stdio.__aexit__(None, None, None)
        try:
            fut = asyncio.run_coroutine_threadsafe(_shutdown(), self._loop)
            fut.result(timeout=15)
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)


class HybridExecutor:
    """ToolRegistry-compatible executor: route MCP-served tools to the real MCP
    server, everything else to the in-process registry. Keeps the PEP boundary
    identical; only the executor behind ALLOW changes for the routed tools."""

    def __init__(self, mcp_router: "McpRouter", fallback_registry, route_prefixes=("filesystem.",)):
        self._mcp = mcp_router
        self._fallback = fallback_registry
        self._prefixes = tuple(route_prefixes)
        self._routed = set(mcp_router._tool_map.keys())

    def execute(self, call) -> str:
        if call.tool in self._routed or call.tool.startswith(self._prefixes):
            if call.tool in self._routed:
                return self._mcp.execute(call)
        return self._fallback.execute(call)

    def routed_tools(self):
        return set(self._routed)
