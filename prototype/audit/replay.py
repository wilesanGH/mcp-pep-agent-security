"""
audit/replay.py — Replay and verify an audit log trace.

Usage:
  python audit/replay.py results/audit_logs/trace_<id>.jsonl
  python audit/replay.py results/audit_logs/trace_<id>.jsonl --verify-only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from audit.logger import AuditLogger

_ACTION_ICON = {"ALLOW": "✅", "DENY": "❌", "REQUIRE_CONFIRM": "⚠️"}
# v8 active label set is {SI:MED, SI:LOW}. The legacy "SI:HIGH" entry is kept
# so that v7 audit logs in results_archive/ still display correctly when
# replayed; the runtime never produces HIGH any more (Task 1.2).
_SI_ICON = {"SI:HIGH": "🔒", "SI:MED": "🔓", "SI:LOW": "⚠️ "}


def replay(log_path: str, verify_only: bool = False) -> None:
    path = Path(log_path)
    if not path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    # Verify chain first
    ok, msg = AuditLogger.verify_chain(log_path)
    chain_status = f"✅ VALID ({msg})" if ok else f"❌ BROKEN — {msg}"

    if verify_only:
        print(f"Chain integrity: {chain_status}")
        sys.exit(0 if ok else 1)

    if not events:
        print("[WARN] Log file is empty.")
        return

    first = events[0]
    print(f"\nTrace:   {first['trace_id']}")
    print(f"Session: {first['session_id']}")
    print(f"Events:  {len(events)}")
    print("═" * 60)

    for i, evt in enumerate(events):
        icon = _ACTION_ICON.get(evt["policy_decision"], "?")
        si = evt["input_labels"].get("SI", "?")
        ds = evt["input_labels"].get("DS", "?")
        si_icon = _SI_ICON.get(si, "?")

        print(f"\nStep {i+1:2d} │ tool: {evt['tool']}")
        print(f"       │ args: {json.dumps(evt['args_redacted'], ensure_ascii=False)}")
        print(f"       │ labels_in: SI={si_icon}{si}, DS={ds}")
        print(f"       │ decision: {icon} {evt['policy_decision']}", end="")

        if evt.get("matched_rule"):
            print(f"  ← {evt['matched_rule']}: {evt['rule_reason']}", end="")
        print()

    print("\n" + "═" * 60)
    print(f"Chain integrity: {chain_status}")

    # Attack outcome summary
    denied = sum(1 for e in events if e["policy_decision"] in ("DENY", "REQUIRE_CONFIRM"))
    allowed = sum(1 for e in events if e["policy_decision"] == "ALLOW")
    print(f"Decisions: {allowed} ALLOW, {denied} DENY/CONFIRM")


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay an MCP-PEP audit log")
    parser.add_argument("log_path", help="Path to trace_*.jsonl file")
    parser.add_argument("--verify-only", action="store_true",
                        help="Only verify chain integrity, no replay output")
    args = parser.parse_args()
    replay(args.log_path, verify_only=args.verify_only)


if __name__ == "__main__":
    main()
