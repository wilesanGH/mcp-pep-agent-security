"""
audit/logger.py — Tamper-evident hash-chained audit log.

Each AuditEvent is appended to a JSONL file.
The hash chain: event_hash = sha256(all fields except event_hash itself).
Any post-hoc modification breaks the chain, detectable via verify_chain().
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from datatypes import AuditEvent, ToolCall, PolicyDecision, TraceState


REDACT_PLACEHOLDER = "<REDACTED:DS:SENSITIVE>"
_DS_SENSITIVE = "DS:SENSITIVE"


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).digest().hex()


def _redact_args(args: dict, ds_label: str) -> dict:
    """Replace all string values in args with placeholder if DS:SENSITIVE."""
    if ds_label != _DS_SENSITIVE:
        return dict(args)
    redacted = {}
    for k, v in args.items():
        redacted[k] = REDACT_PLACEHOLDER if isinstance(v, str) else v
    return redacted


def _compute_event_hash(event_dict: dict) -> str:
    """Hash all fields except event_hash itself."""
    payload = {k: v for k, v in event_dict.items() if k != "event_hash"}
    return _sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False))


class AuditLogger:
    """
    Writes AuditEvents to a per-trace JSONL file with a hash chain.

    Usage:
        logger = AuditLogger(log_dir="results/audit_logs", session_id="sess_001")
        logger.log(call, decision, trace_state)
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, log_dir: str, session_id: str):
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._session_id = session_id
        # per-trace state: trace_id -> (last_hash, file_path)
        self._trace_state: dict[str, tuple[str, Path]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        call: ToolCall,
        decision: PolicyDecision,
        trace_state: TraceState,
    ) -> AuditEvent:
        """Build and persist one AuditEvent. Returns the written event."""
        prev_hash, log_path = self._get_or_init_trace(call.trace_id)

        args_hash = _sha256(
            json.dumps(call.args, sort_keys=True, ensure_ascii=False)
        )
        args_redacted = _redact_args(call.args, decision.evaluated_ds)

        event_dict = {
            "event_id": str(uuid.uuid4()),
            "trace_id": call.trace_id,
            "session_id": self._session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": call.tool,
            "args_hash": args_hash,
            "args_redacted": args_redacted,
            "input_labels": {
                "SI": decision.evaluated_si,
                "DS": decision.evaluated_ds,
            },
            "policy_decision": decision.action,
            "matched_rule": decision.matched_rule or "",
            "rule_reason": decision.reason,
            "prev_event_hash": prev_hash,
            "event_hash": "",  # placeholder; computed below
        }
        # JISA v8: include filesystem path-normalization metadata when present.
        # Only filesystem tools carry this; for everything else PolicyDecision.path_norm
        # is None and the keys are omitted, so existing v7 audit-log shape is preserved
        # for non-filesystem events.
        path_norm = getattr(decision, "path_norm", None)
        if path_norm:
            event_dict["raw_path"] = path_norm.get("raw_path")
            event_dict["normalized_path"] = path_norm.get("normalized_path")
            event_dict["path_normalization_error"] = path_norm.get("path_normalization_error")
        event_dict["event_hash"] = _compute_event_hash(event_dict)

        # Persist
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_dict, ensure_ascii=False) + "\n")

        # Update chain state
        self._trace_state[call.trace_id] = (event_dict["event_hash"], log_path)

        return AuditEvent(**event_dict)

    def get_log_path(self, trace_id: str) -> Optional[Path]:
        entry = self._trace_state.get(trace_id)
        return entry[1] if entry else None

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    @staticmethod
    def verify_chain(log_path: str) -> tuple[bool, str]:
        """
        Verify the hash chain of a JSONL audit log.

        Returns:
            (True, "OK") if chain is intact.
            (False, reason) if any link is broken.
        """
        path = Path(log_path)
        if not path.exists():
            return False, f"Log file not found: {log_path}"

        events = []
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    return False, f"JSON parse error at line {i+1}: {e}"

        if not events:
            return False, "Log file is empty"

        expected_prev = AuditLogger.GENESIS_HASH
        for i, evt in enumerate(events):
            # Check prev_event_hash linkage
            if evt["prev_event_hash"] != expected_prev:
                return False, (
                    f"Chain broken at event {i+1} ({evt['event_id']}): "
                    f"expected prev_hash={expected_prev[:16]}… "
                    f"got {evt['prev_event_hash'][:16]}…"
                )
            # Recompute event_hash
            recomputed = _compute_event_hash(evt)
            if recomputed != evt["event_hash"]:
                return False, (
                    f"Hash mismatch at event {i+1} ({evt['event_id']}): "
                    f"stored={evt['event_hash'][:16]}… "
                    f"recomputed={recomputed[:16]}…"
                )
            expected_prev = evt["event_hash"]

        return True, f"OK ({len(events)} events verified)"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_init_trace(self, trace_id: str) -> tuple[str, Path]:
        if trace_id not in self._trace_state:
            log_path = self._log_dir / f"trace_{trace_id}.jsonl"
            self._trace_state[trace_id] = (self.GENESIS_HASH, log_path)
        return self._trace_state[trace_id]
