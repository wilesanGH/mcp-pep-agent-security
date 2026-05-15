#!/usr/bin/env python3
"""
verify_chain.py — Standalone hash-chain verifier for the JISA reviewer pack.

Reproduces the chain-verification logic of prototype/audit/logger.py
without any project imports. Works with Python 3.7+ stdlib only.

Hash convention (mirrors AuditLogger._compute_event_hash):
    event_hash = sha256(
        json.dumps({all fields except 'event_hash'},
                   sort_keys=True, ensure_ascii=False)
    )

Genesis: prev_event_hash for the first event of each trace = "0" * 64.

Usage:
    python3 verify_chain.py audit_log_samples/
    python3 verify_chain.py path/to/trace_xxxxx.jsonl
    python3 verify_chain.py --all reviewer-pack/

Exit code 0 if every file passes; 1 if any file fails.
"""

import hashlib
import json
import sys
from pathlib import Path

GENESIS_HASH = "0" * 64


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def compute_event_hash(event: dict) -> str:
    payload = {k: v for k, v in event.items() if k != "event_hash"}
    return sha256_hex(json.dumps(payload, sort_keys=True, ensure_ascii=False))


def verify_one(path: Path) -> tuple[bool, list]:
    issues = []
    prev_hash = GENESIS_HASH
    n = 0

    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as e:
                issues.append(f"  line {line_no}: malformed JSON: {e}")
                return False, issues

            n += 1

            # 1. prev_event_hash must match previous event's event_hash (or genesis)
            stored_prev = ev.get("prev_event_hash", "")
            if stored_prev != prev_hash:
                issues.append(
                    f"  line {line_no}: prev_event_hash mismatch — "
                    f"expected {prev_hash[:16]}…, got {stored_prev[:16]}…"
                )
                return False, issues

            # 2. event_hash must equal recomputed hash
            stored = ev.get("event_hash", "")
            recomputed = compute_event_hash(ev)
            if stored != recomputed:
                issues.append(
                    f"  line {line_no}: event_hash mismatch — "
                    f"stored {stored[:16]}…, recomputed {recomputed[:16]}…"
                )
                return False, issues

            prev_hash = stored

    return True, [f"  events: {n}, all hashes consistent"]


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2

    target = Path(argv[1])
    if not target.exists():
        print(f"path not found: {target}", file=sys.stderr)
        return 2

    if target.is_file():
        files = [target]
    else:
        files = sorted(target.rglob("trace_*.jsonl"))
        # Also accept other audit-style jsonl
        if not files:
            files = sorted(target.rglob("*.jsonl"))

    if not files:
        print(f"no .jsonl files found under {target}", file=sys.stderr)
        return 2

    print(f"Verifying {len(files)} audit log file(s) under {target}\n")
    pass_count = 0
    fail_count = 0
    for f in files:
        ok, lines = verify_one(f)
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {f.relative_to(target.parent if target.is_file() else target)}")
        for ln in lines:
            print(ln)
        if ok:
            pass_count += 1
        else:
            fail_count += 1

    print(f"\nSummary: {pass_count} PASS, {fail_count} FAIL out of {len(files)} files")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
