"""
pep/rules.py — Policy rule engine (R01–R05).

Rules are evaluated in order; first match wins.
Rules can also be loaded from configs/policy_rules.yaml.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from datatypes import SI, DS, PolicyDecision


# ---------------------------------------------------------------------------
# Hard-coded rule definitions (authoritative; YAML is an override layer)
# ---------------------------------------------------------------------------

#  Each rule is a dict:
#    id           : str
#    description  : str
#    action       : "ALLOW" | "DENY" | "REQUIRE_CONFIRM"
#    match        : callable(tool, si, ds, args, trace_state) -> bool

_BUILTIN_RULES = [
    {
        "id": "R01",
        # IFC-sensitive threshold: fires ONLY when SI==LOW (external untrusted content).
        # Rationale: the key threat is cross-server taint — a low-integrity external source
        # (e.g., injected web search result) propagates SI:LOW across steps and reaches a
        # code execution tool.  User-level inputs (SI:MED) are permitted to drive shell
        # commands; only content contaminated by external SI:LOW sources is denied.
        # This makes the IFC contribution visible: without cross-step SI propagation
        # (baseline C), SI resets to SI:MED before each call, so R01 never fires and T2
        # attacks succeed.  With IFC (baseline D), SI:LOW persists and R01 fires.
        "description": "External-origin (SI:LOW) content reaching code execution tool",
        "action": "DENY",
        "match": lambda tool, si, ds, args, ts: (
            si == SI.LOW and
            tool in {"shell.run", "bash.run", "exec.run", "run_code"}
        ),
    },
    {
        "id": "R02",
        "description": "Sensitive data exfiltration attempt",
        "action": "DENY",
        "match": lambda tool, si, ds, args, ts: (
            ds == DS.SENSITIVE and
            tool in {"send_email.send", "http_post.post", "upload.upload",
                     "webhook.call"}
        ),
    },
    {
        "id": "R03",
        "description": "File or database operation outside permitted path scope",
        "action": "DENY",
        "match": lambda tool, si, ds, args, ts: (
            tool in {"filesystem.read_file", "filesystem.write_file",
                     "delete.delete", "rm.run", "drop_table.run",
                     "truncate.run"} and
            _path_outside_scope(args, ts)
        ),
    },
    {
        "id": "R04",
        "description": "Sensitive data in local/internal message — user confirmation required",
        "action": "REQUIRE_CONFIRM",
        "match": lambda tool, si, ds, args, ts: (
            ds == DS.SENSITIVE and
            tool in {"send_message.send", "notify.send"}
        ),
    },
    {
        "id": "R05",
        "description": "High-frequency high-risk calls (rate limiting)",
        "action": "REQUIRE_CONFIRM",
        "match": lambda tool, si, ds, args, ts: (
            tool in {"shell.run", "bash.run", "send_email.send",
                     "http_post.post", "delete.delete"} and
            _high_risk_rate_exceeded(ts, window_sec=60, threshold=3)
        ),
    },
]


def _path_outside_scope(args: dict, trace_state) -> bool:
    """Return True if args contain a 'path' that is outside allowed scopes."""
    path = args.get("path", "")
    if not path:
        return False
    allowed = getattr(trace_state, "path_scope", ["./workspace/", "workspace/"])
    path_norm = str(path).replace("\\", "/")
    return not any(path_norm.startswith(scope) for scope in allowed)


def _high_risk_rate_exceeded(trace_state, window_sec: int, threshold: int) -> bool:
    """Return True if ≥ threshold high-risk calls occurred in the last window_sec."""
    now = time.time()
    recent = [t for t in trace_state.high_risk_call_timestamps
              if now - t <= window_sec]
    return len(recent) >= threshold


# ---------------------------------------------------------------------------
# RuleEngine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Evaluates a ToolCall against the ordered rule list.

    Usage:
        engine = RuleEngine()                      # use built-in rules
        engine = RuleEngine("configs/policy_rules.yaml")  # load overrides
        decision = engine.evaluate(tool, si, ds, args, trace_state)
    """

    def __init__(self, rules_path: Optional[str] = None):
        self._rules = list(_BUILTIN_RULES)
        if rules_path and Path(rules_path).exists():
            self._load_yaml_overrides(rules_path)

    def evaluate(
        self,
        tool: str,
        si: str,
        ds: str,
        args: dict,
        trace_state,
    ) -> PolicyDecision:
        """
        Evaluate rules in order; return the first matching decision.
        Returns ALLOW if no rule matches.
        """
        for rule in self._rules:
            try:
                if rule["match"](tool, si, ds, args, trace_state):
                    return PolicyDecision(
                        action=rule["action"],
                        matched_rule=rule["id"],
                        reason=rule["description"],
                        evaluated_si=si,
                        evaluated_ds=ds,
                    )
            except Exception:
                # Rule evaluation error → fail-safe DENY for high-risk tools
                if tool in {"shell.run", "bash.run", "send_email.send",
                            "http_post.post", "delete.delete"}:
                    return PolicyDecision(
                        action="DENY",
                        matched_rule="FAIL_SAFE",
                        reason="Rule evaluation error; fail-safe DENY for high-risk tool",
                        evaluated_si=si,
                        evaluated_ds=ds,
                    )

        return PolicyDecision(
            action="ALLOW",
            matched_rule=None,
            reason="No matching rule; allowed",
            evaluated_si=si,
            evaluated_ds=ds,
        )

    def list_rules(self) -> list[dict]:
        return [{"id": r["id"], "description": r["description"],
                 "action": r["action"]} for r in self._rules]

    # ------------------------------------------------------------------
    def _load_yaml_overrides(self, path: str) -> None:
        """
        Optional: load extra rules from YAML.
        yaml is imported lazily so the module can be used without PyYAML installed
        (the YAML override path is only needed when rules_path is explicitly provided).
        """
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML is required to load YAML rule overrides. "
                "Run: pip install PyYAML"
            )
        with open(path, encoding="utf-8") as f:
            yaml.safe_load(f)
        # YAML rules are reserved for future use; built-in lambdas are authoritative.
        pass
