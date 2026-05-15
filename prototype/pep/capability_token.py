"""
pep/capability_token.py — Capability Token loader and checker.

Two token files are used in experiments:
  configs/attack_token.json  — allows shell + send_email (attack experiments)
  configs/normal_token.json  — allows only filesystem + web_search (normal tasks)

Unrecognized servers default to SI:LOW (fail-safe).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from datatypes import SI


class CapabilityToken:
    """
    Loads a capability token JSON and exposes policy checks.

    Token format:
    {
      "session_id": "...",
      "allow_tools": ["filesystem.read_file", ...],
      "path_scope": ["./workspace/"],
      "max_calls_per_tool": {"send_email.send": 10},
      "server_source_integrity": {"filesystem": "SI:MED", ...},
      "server_data_sensitivity_policy": {"filesystem": "detect"}
    }
    """

    def __init__(self, token_path: str):
        path = Path(token_path)
        if not path.exists():
            raise FileNotFoundError(f"Capability token not found: {token_path}")
        with open(path, encoding="utf-8") as f:
            self._data = json.load(f)
        self._call_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._data.get("session_id", "unknown")

    @property
    def path_scope(self) -> list[str]:
        return self._data.get("path_scope", ["./workspace/"])

    # ------------------------------------------------------------------
    # Policy checks
    # ------------------------------------------------------------------

    def check_tool_allowed(self, tool: str) -> bool:
        """Return True if the tool appears in allow_tools."""
        return tool in self._data.get("allow_tools", [])

    def get_server_si(self, server: str) -> str:
        """
        Return the SI label for a server.
        server = first component of tool name, e.g. "filesystem" from "filesystem.read_file".
        Defaults to SI.LOW if not configured (fail-safe).

        Legacy "SI:HIGH" values from v7-era tokens are normalised to SI:MED
        (see SI.normalize) so older configs continue to load correctly.
        """
        mapping = self._data.get("server_source_integrity", {})
        return SI.normalize(mapping.get(server, SI.LOW))

    def check_path_scope(self, path: str) -> bool:
        """Return True if path is within an allowed scope."""
        path_norm = str(path).replace("\\", "/")
        return any(path_norm.startswith(s) for s in self.path_scope)

    def check_call_limit(self, tool: str) -> bool:
        """
        Return True if tool has not exceeded its max_calls_per_tool limit.
        Tools not listed in max_calls_per_tool have no limit.
        """
        limits = self._data.get("max_calls_per_tool", {})
        if tool not in limits:
            return True
        limit = limits[tool]
        current = self._call_counts.get(tool, 0)
        return current < limit

    def record_call(self, tool: str) -> None:
        """Increment the call counter for a tool (call after ALLOW)."""
        self._call_counts[tool] = self._call_counts.get(tool, 0) + 1

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def server_from_tool(self, tool: str) -> str:
        """Extract server name: 'filesystem.read_file' -> 'filesystem'."""
        return tool.split(".")[0] if "." in tool else tool

    def get_tool_si(self, tool: str) -> str:
        """Convenience: get SI for the server that owns this tool."""
        return self.get_server_si(self.server_from_tool(tool))

    @classmethod
    def for_attack(cls, configs_dir: str = "configs") -> "CapabilityToken":
        return cls(str(Path(configs_dir) / "attack_token.json"))

    @classmethod
    def for_normal(cls, configs_dir: str = "configs") -> "CapabilityToken":
        return cls(str(Path(configs_dir) / "normal_token.json"))
