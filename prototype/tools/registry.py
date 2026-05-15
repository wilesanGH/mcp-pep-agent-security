"""
tools/registry.py — Tool registry: maps tool names to implementations.
"""

from __future__ import annotations

from datatypes import ToolCall


class ToolRegistry:
    """
    Maps tool names like "filesystem.read_file" to Python callables.
    Each callable receives the args dict and returns a string result.
    """

    def __init__(self):
        self._tools: dict[str, callable] = {}

    def register(self, name: str, fn: callable) -> None:
        self._tools[name] = fn

    def execute(self, call: ToolCall) -> str:
        if call.tool not in self._tools:
            return f"[ERROR: unknown tool '{call.tool}']"
        try:
            # Inject trace_id as a meta-argument so tools can tag their records.
            # Tools that don't use it simply ignore this key.
            args = {**call.args, "__trace_id__": call.trace_id}
            return self._tools[call.tool](args)
        except Exception as e:
            return f"[ERROR: {call.tool} raised {type(e).__name__}: {e}]"

    def list_tools(self) -> list[str]:
        return sorted(self._tools.keys())


def build_default_registry(
    workspace_dir: str = "workspace",
    web_content_dir: str = "datasets",
    results_dir: str = "results",
) -> ToolRegistry:
    """Build a ToolRegistry with all mock tools pre-registered."""
    from tools.filesystem import FilesystemTool
    from tools.mock_web import MockWebSearch
    from tools.mock_email import MockEmail
    from tools.mock_shell import MockShell

    fs = FilesystemTool(workspace_dir)
    web = MockWebSearch(web_content_dir)
    email = MockEmail(results_dir)
    shell = MockShell(results_dir)

    reg = ToolRegistry()
    reg.register("filesystem.read_file",  fs.read_file)
    reg.register("filesystem.write_file", fs.write_file)
    reg.register("web_search.search",     web.search)
    reg.register("send_email.send",       email.send)
    reg.register("shell.run",             shell.run)
    return reg
