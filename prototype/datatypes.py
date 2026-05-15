"""
datatypes.py — Shared data structures for the MCP-PEP prototype.

All inter-module interfaces use these types. Define once, never change.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# SI / DS label constants
# ---------------------------------------------------------------------------

class SI:
    """
    Source-Integrity label set.

    JISA v8 (Task 1.2): two-level system. v7 also had ``HIGH`` but it was
    never reachable as a trace state (traces start at MED and SI propagates
    via ``min()``), so the label was dead code that misled reviewers. We
    keep ``normalize()`` as a backward-compat shim so audit logs and token
    configs that still carry the old ``"SI:HIGH"`` string parse correctly:
    HIGH gets folded into MED on read.
    """
    MED  = "SI:MED"
    LOW  = "SI:LOW"

    _ORDER = {MED: 1, LOW: 0}
    # v7 → v8 compatibility: legacy "SI:HIGH" strings (still present in
    # results_archive/v7_single_run/ audit logs and in any unmigrated token
    # config) are treated as SI:MED, matching the v7 runtime behaviour where
    # min(MED, HIGH) was always MED anyway.
    _LEGACY = {"SI:HIGH": MED}

    @classmethod
    def normalize(cls, label: str) -> str:
        """Fold any legacy SI label into the v8 set (HIGH → MED)."""
        return cls._LEGACY.get(label, label)

    @classmethod
    def min(cls, a: str, b: str) -> str:
        """Return the lower-integrity label (conservative merge)."""
        a, b = cls.normalize(a), cls.normalize(b)
        return a if cls._ORDER[a] <= cls._ORDER[b] else b

    @classmethod
    def lt(cls, a: str, b: str) -> bool:
        """True if a has strictly lower integrity than b."""
        a, b = cls.normalize(a), cls.normalize(b)
        return cls._ORDER[a] < cls._ORDER[b]


class DS:
    SENSITIVE = "DS:SENSITIVE"
    NORMAL    = "DS:NORMAL"

    @classmethod
    def merge(cls, a: str, b: str) -> str:
        """DS is sticky: SENSITIVE wins over NORMAL."""
        return cls.SENSITIVE if cls.SENSITIVE in (a, b) else cls.NORMAL


# ---------------------------------------------------------------------------
# Core data types
# ---------------------------------------------------------------------------

@dataclass
class LabeledData:
    """A piece of data flowing through the system, with trust labels attached."""
    value: str
    si: str           # SI.MED | SI.LOW
    ds: str           # DS.SENSITIVE | DS.NORMAL
    source_tool: str  # name of the tool that produced this data
    trace_id: str


@dataclass
class ToolCall:
    """A tool invocation request from the LLM, before policy evaluation."""
    tool: str          # e.g. "send_email.send"
    args: dict         # raw arguments from LLM
    trace_id: str
    step: int          # call index within this trace (0-based)


@dataclass
class PolicyDecision:
    """Result of PEP evaluation for one tool call."""
    action: str                    # "ALLOW" | "DENY" | "REQUIRE_CONFIRM"
    matched_rule: Optional[str]    # e.g. "R02"; None when ALLOW
    reason: str
    evaluated_si: str              # SI label at decision time
    evaluated_ds: str              # DS label at decision time
    # JISA v8: filesystem path normalization metadata. None for non-filesystem
    # tools. When present, AuditLogger emits raw_path / normalized_path /
    # path_normalization_error fields so the audit record explains exactly
    # what R03 saw.
    path_norm: Optional[dict] = None


@dataclass
class AuditEvent:
    """One immutable audit record, part of a hash-chained log."""
    event_id: str
    trace_id: str
    session_id: str
    timestamp: str          # ISO 8601
    tool: str
    args_hash: str          # sha256 of json.dumps(args, sort_keys=True)
    args_redacted: dict     # DS:SENSITIVE values replaced with placeholder
    input_labels: dict      # {"SI": ..., "DS": ...}
    policy_decision: str    # "ALLOW" | "DENY" | "REQUIRE_CONFIRM"
    matched_rule: str       # empty string when ALLOW
    rule_reason: str
    prev_event_hash: str
    event_hash: str         # sha256 over all fields except event_hash itself
    # JISA v8 path-normalization fields (filesystem tools only; None otherwise).
    raw_path: Optional[str] = None
    normalized_path: Optional[str] = None
    path_normalization_error: Optional[str] = None


@dataclass
class TraceState:
    """Accumulated label state for an ongoing agent trace."""
    trace_id: str
    session_id: str
    current_si: str = SI.MED    # starts at user level; degrades as tools return
    current_ds: str = DS.NORMAL # sticky: once SENSITIVE, never resets
    step: int = 0
    high_risk_call_timestamps: list = field(default_factory=list)


@dataclass
class RunResult:
    """Final result of one agent run (one task or attack sample)."""
    trace_id: str
    task_id: str
    baseline: str
    final_state: TraceState
    messages: list              # full conversation history
    audit_log_path: str
    task_completed: bool = False
    attack_blocked: bool = False  # True if attack did NOT reach its goal
    model: str = ""              # LLM model identifier (empty in scripted mode)
    error: Optional[str] = None
