"""
pep/label_tracker.py — Trace-level SI/DS label propagation (IFC).

Granularity: coarse (trace-level).
  - SI  : current_si = min(current_si, new_result_si)  — degrades, never recovers
  - DS  : sticky — once DS:SENSITIVE, stays SENSITIVE for the trace lifetime

This is intentionally simple for the MVP.  The trade-off (higher FPR) is
discussed in the paper's §5 Discussion as a motivation for future argument-level
taint tracking.
"""

from __future__ import annotations

import time
import uuid

from datatypes import SI, DS, TraceState, LabeledData


class LabelTracker:
    """
    Maintains TraceState for all active traces.

    Baseline behavior is controlled by the `ifc_enabled` flag:
      ifc_enabled=True  → Full system (baseline D): SI accumulates across steps
      ifc_enabled=False → Runtime ablation (baseline C): SI resets each step
    """

    def __init__(self, ifc_enabled: bool = True, path_scope: list[str] | None = None):
        self._ifc_enabled = ifc_enabled
        self._path_scope = path_scope or ["./workspace/", "workspace/"]
        self._traces: dict[str, TraceState] = {}

    # ------------------------------------------------------------------
    # Trace lifecycle
    # ------------------------------------------------------------------

    def init_trace(
        self,
        session_id: str,
        trace_id: str | None = None,
    ) -> TraceState:
        """
        Create a new TraceState.
        Initial SI = SI:MED (user-level input, per threat model §6).
        """
        tid = trace_id or str(uuid.uuid4()).replace("-", "")[:16]
        state = TraceState(
            trace_id=tid,
            session_id=session_id,
            current_si=SI.MED,
            current_ds=DS.NORMAL,
            step=0,
        )
        state.path_scope = list(self._path_scope)  # attach for R03 path checks
        self._traces[tid] = state
        return state

    def get_state(self, trace_id: str) -> TraceState:
        if trace_id not in self._traces:
            raise KeyError(f"Unknown trace_id: {trace_id}")
        return self._traces[trace_id]

    # ------------------------------------------------------------------
    # Label propagation
    # ------------------------------------------------------------------

    def get_labels_for_call(self, trace_id: str) -> tuple[str, str]:
        """
        Return (si, ds) to use when evaluating the next tool call.

        Baseline C (ifc_enabled=False): SI resets to SI:MED each call,
        so cross-step SI propagation is disabled.  DS accumulation is
        retained even in C (DS detection is a separate mechanism).
        """
        state = self._traces[trace_id]
        si = state.current_si if self._ifc_enabled else SI.MED
        return si, state.current_ds

    def update_after_tool_return(
        self,
        trace_id: str,
        result: LabeledData,
    ) -> TraceState:
        """
        Update TraceState after a tool returns a LabeledData result.

        SI rule : current_si = min(current_si, result.si)
        DS rule : current_ds = SENSITIVE if either is SENSITIVE (sticky)
        """
        state = self._traces[trace_id]
        state.current_si = SI.min(state.current_si, result.si)
        state.current_ds = DS.merge(state.current_ds, result.ds)
        state.step += 1
        return state

    def record_high_risk_call(self, trace_id: str) -> None:
        """Record timestamp of a high-risk call for R05 rate limiting."""
        state = self._traces[trace_id]
        state.high_risk_call_timestamps.append(time.time())

    def mark_intent_tainted(self, trace_id: str, reason: str) -> None:
        """
        Mark a trace as intent-tainted (conservative-DS policy, baseline D-IT).

        Called by the enforcer when the trace attempts a protected-source read
        (an out-of-scope filesystem.read_file denied by R03). Once set, the
        enforcer (with conservative_intent_ds=True) forces subsequent outbound
        high-risk calls to DS:SENSITIVE so R02 fires on model-reconstructed
        exfiltration that the regex DS detector would otherwise miss. Idempotent:
        the first triggering reason is preserved for audit reproducibility.
        """
        state = self._traces[trace_id]
        if not state.intent_tainted:
            state.intent_tainted = True
            state.intent_taint_reason = reason

    def advance_step(self, trace_id: str) -> None:
        """Increment step counter without updating labels (used on DENY)."""
        self._traces[trace_id].step += 1

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def summary(self, trace_id: str) -> dict:
        s = self._traces[trace_id]
        return {
            "trace_id": s.trace_id,
            "step": s.step,
            "current_si": s.current_si,
            "current_ds": s.current_ds,
            "ifc_enabled": self._ifc_enabled,
            "intent_tainted": s.intent_tainted,
            "intent_taint_reason": s.intent_taint_reason,
        }
