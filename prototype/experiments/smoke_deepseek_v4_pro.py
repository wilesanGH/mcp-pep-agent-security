"""
smoke_deepseek_v4_pro.py — Task 0.5a end-to-end smoke test.

Per JISA v8 protocol §3.4 Task 0.5a, this script validates that:
  1. The provider preset update (Task 0.5a Step 1) is wired correctly.
  2. The full agent loop (model + tools + PEP + audit) works end-to-end on
     deepseek-v4-pro, before path-normalization or label-system changes.

Procedure:
  - Load 4 sample tasks from MVP-30: T1-001 / T2-001 / T3-001 / N-001
  - Run baseline = full (= the v7 D, since path-norm is not yet implemented)
  - For each task, classify run validity into one of 5 categories (§5)
  - Verify audit log exists and chain validates
  - Apply 7 acceptance conditions (§3.4 Task 0.5a)

Pass / fail is decided by §3.4 Task 0.5a acceptance:
  [a] All 4 tasks complete without HARNESS_ERROR
  [b] 0 PROVIDER_ERROR (single-shot, low load)
  [c] At least 3 of 4 tasks produce VALID_TOOL_TRACE (T1-001 may legitimately POLICY_DENIED)
  [d] Audit chain verification passes for every produced log file
  [e] Per-run record schema populates correctly (mandatory fields present)
  [f] Provider preset patch landed and LLMClient(backend='deepseek') succeeds
  [g] results_jisa_v8/mock_outputs/ directory exists

Usage:
  python experiments/smoke_deepseek_v4_pro.py
  python experiments/smoke_deepseek_v4_pro.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROTO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTO_ROOT))

from audit.logger import AuditLogger  # noqa: E402
from llm_client import LLMClient  # noqa: E402

PILOT_DIR = PROTO_ROOT / "results_jisa_v8" / "pilot"
MOCK_OUTPUTS_DIR = PROTO_ROOT / "results_jisa_v8" / "mock_outputs"
PROTOCOL_FILE = PROTO_ROOT / "experiments" / "jisa_v8_protocol.md"

SMOKE_TASKS = ["T1-001", "T2-001", "T3-001", "N-001"]
SMOKE_BASELINE = "full"   # D in v7 nomenclature; v8 D (with path-norm) lands in Task 1.1
SMOKE_BACKEND = "deepseek"
SMOKE_MODEL = "deepseek-v4-pro"


def read_protocol_version() -> str:
    """Parse the canonical protocol version from the protocol markdown.

    Reads the first ``**Protocol version:** vX.Y.Z`` line and returns the
    version token. Falls back to ``"unknown"`` if the file cannot be parsed
    so the smoke run still completes; the smoke summary then visibly shows
    the parse failure rather than a stale hard-coded version.

    Stamping the smoke summary directly from the protocol file (rather than
    a constant in this script) is the v8.1.1 fix for the "protocol_version
    drift" reviewer-flagged class of bug.
    """
    import re
    try:
        with open(PROTOCOL_FILE, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\*\*Protocol version:\*\*\s+(v\d+\.\d+\.\d+)", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return "unknown"

REQUIRED_RECORD_FIELDS = [
    "task_id", "baseline", "model",
    "total_calls", "deny_count", "allow_count",
    "hr_total", "hr_allowed",
    "chain_valid", "trace_id", "audit_log",
    "task_completed", "attack_blocked",
    "elapsed_s", "error",
]


# ---------------------------------------------------------------------------
# Validity classification (§5 of protocol)
# ---------------------------------------------------------------------------

def classify_validity(record: dict) -> str:
    """
    Classify a run record into one of the 5 §5 categories.
    Decision tree per protocol §5.1:
      1. HARNESS_ERROR — local code/adapter failure
      2. PROVIDER_ERROR — API timeout/5xx/auth/etc.
      3. POLICY_DENIED — issued ≥1 tool call AND any was DENY/REQUIRE_CONFIRM
      4. VALID_TOOL_TRACE — issued ≥1 tool call without policy denial
      5. VALID_NO_TOOL_CALL — model answered with no tool call
    """
    err = record.get("error")
    if err:
        # Heuristic: errors with API/timeout/HTTP keywords are provider-side;
        # otherwise treat as harness-side. This is approximate; Task 1.5
        # introduces explicit classification at runtime.
        err_l = str(err).lower()
        provider_markers = (
            "api", "timeout", "http", "openai", "ratelimit",
            "rate_limit", "503", "502", "504", "500", "401", "403",
            "connection", "reset", "schema", "tool_call",
        )
        if any(m in err_l for m in provider_markers):
            return "PROVIDER_ERROR"
        return "HARNESS_ERROR"

    total_calls = record.get("total_calls", 0)
    deny_count = record.get("deny_count", 0)

    if total_calls == 0:
        return "VALID_NO_TOOL_CALL"
    if deny_count > 0:
        return "POLICY_DENIED"  # subset of VALID_TOOL_TRACE; counted as valid
    return "VALID_TOOL_TRACE"


def is_valid_status(status: str) -> bool:
    """Whether a status counts as a valid-run for main metrics."""
    return status in {"VALID_TOOL_TRACE", "VALID_NO_TOOL_CALL", "POLICY_DENIED"}


# ---------------------------------------------------------------------------
# Acceptance criteria
# ---------------------------------------------------------------------------

def check_acceptance(records: list[dict], llm_client_ok: bool, mock_dir_ok: bool) -> tuple[bool, list[dict]]:
    """Returns (pass, list of per-criterion results)."""
    n = len(records)
    statuses = [classify_validity(r) for r in records]
    n_harness = sum(1 for s in statuses if s == "HARNESS_ERROR")
    n_provider = sum(1 for s in statuses if s == "PROVIDER_ERROR")
    n_valid_tool = sum(1 for s in statuses if s == "VALID_TOOL_TRACE")
    n_policy_denied = sum(1 for s in statuses if s == "POLICY_DENIED")
    n_valid = sum(1 for s in statuses if is_valid_status(s))

    n_chain_ok = sum(1 for r in records if r.get("chain_valid") is True)
    n_chain_with_calls = sum(1 for r in records if r.get("total_calls", 0) > 0)

    schema_ok = all(
        all(field in r for field in REQUIRED_RECORD_FIELDS)
        for r in records
    )

    checks = [
        {
            "id": "a",
            "desc": "All 4 tasks complete without HARNESS_ERROR",
            "pass": n_harness == 0 and n == 4,
            "detail": f"harness_errors={n_harness}, total_runs={n}",
        },
        {
            "id": "b",
            "desc": "0 PROVIDER_ERROR (single-shot, low load)",
            "pass": n_provider == 0,
            "detail": f"provider_errors={n_provider}",
        },
        {
            "id": "c",
            "desc": "≥3 of 4 tasks produce VALID_TOOL_TRACE or POLICY_DENIED",
            "pass": (n_valid_tool + n_policy_denied) >= 3,
            "detail": f"valid_tool_trace={n_valid_tool}, policy_denied={n_policy_denied}",
        },
        {
            "id": "d",
            "desc": "Audit chain verification passes for every trace with ≥1 call",
            "pass": n_chain_ok >= n_chain_with_calls and n_chain_with_calls > 0,
            "detail": f"chain_ok={n_chain_ok}/{n_chain_with_calls} traces with calls",
        },
        {
            "id": "e",
            "desc": "Per-run record schema populates correctly",
            "pass": schema_ok,
            "detail": "all required fields present" if schema_ok else "missing fields",
        },
        {
            "id": "f",
            "desc": "Provider preset patch landed (LLMClient(backend='deepseek') OK)",
            "pass": llm_client_ok,
            "detail": "init OK" if llm_client_ok else "init failed",
        },
        {
            "id": "g",
            "desc": "results_jisa_v8/mock_outputs/ directory exists",
            "pass": mock_dir_ok,
            "detail": "directory present" if mock_dir_ok else "directory MISSING",
        },
    ]
    overall = all(c["pass"] for c in checks)
    return overall, checks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def precheck_llm_client() -> bool:
    """Test that LLMClient(backend='deepseek') initialises with DEEPSEEK_TOKEN."""
    try:
        c = LLMClient(backend=SMOKE_BACKEND, model=SMOKE_MODEL)
        return c._model == SMOKE_MODEL
    except Exception:
        return False


def precheck_mock_outputs_dir() -> bool:
    return MOCK_OUTPUTS_DIR.is_dir()


def reverify_chain(audit_log_path: str) -> tuple[bool, str]:
    """Run AuditLogger.verify_chain() on a single log file, return (ok, reason)."""
    if not audit_log_path:
        return False, "no audit_log path in record"
    p = Path(audit_log_path)
    if not p.is_absolute():
        p = PROTO_ROOT / p
    if not p.exists():
        # No-tool-call traces have no log file; chain "validity" for them is
        # by convention reported as False but it's not a tamper failure.
        return False, "log file does not exist (no-tool-call trace)"
    try:
        ok, reason = AuditLogger.verify_chain(str(p))
        return bool(ok), reason or "OK"
    except Exception as e:
        return False, f"verify_chain raised: {e}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="show plan only")
    args = ap.parse_args()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    run_eval_output = PILOT_DIR / f"smoke_deepseek_v4_pro_{timestamp}.json"
    summary_output = PILOT_DIR / f"smoke_test_{timestamp}.json"

    PILOT_DIR.mkdir(parents=True, exist_ok=True)

    plan = {
        "tasks": SMOKE_TASKS,
        "baseline": SMOKE_BASELINE,
        "backend": SMOKE_BACKEND,
        "model": SMOKE_MODEL,
        "run_eval_output": str(run_eval_output),
        "summary_output": str(summary_output),
    }
    print("=" * 78)
    print(f"Task 0.5a end-to-end smoke test  ({timestamp})")
    print("=" * 78)
    print(json.dumps(plan, indent=2))
    print()

    # Pre-checks (don't depend on running the eval)
    print("Pre-checks")
    print("-" * 78)
    llm_ok = precheck_llm_client()
    mock_dir_ok = precheck_mock_outputs_dir()
    print(f"  [f] LLMClient(backend='deepseek', model='deepseek-v4-pro'): {'OK' if llm_ok else 'FAILED'}")
    print(f"  [g] results_jisa_v8/mock_outputs/ exists: {'YES' if mock_dir_ok else 'NO'}")
    print()

    if args.dry_run:
        print("Dry run — exiting without invoking run_eval.")
        return 0

    # Invoke run_eval.py
    # Anchor v8 audit logs + mock outputs under results_jisa_v8/ via the
    # new --results-dir flag (added 2026-05-02 in run_eval.py for JISA v8).
    v8_results_root = PROTO_ROOT / "results_jisa_v8"
    cmd = [
        sys.executable, "-u",
        str(PROTO_ROOT / "experiments" / "run_eval.py"),
        "--mode", "llm",
        "--backend", SMOKE_BACKEND,
        "--model", SMOKE_MODEL,
        "--baselines", SMOKE_BASELINE,
        "--samples", *SMOKE_TASKS,
        "--output", str(run_eval_output),
        "--results-dir", str(v8_results_root),
    ]
    print("Invoking run_eval.py")
    print("-" * 78)
    print(" ".join(cmd[:3]) + " " + " ".join(repr(a) for a in cmd[3:]))
    print()

    t0 = time.perf_counter()
    proc = subprocess.run(cmd, cwd=str(PROTO_ROOT), capture_output=False)
    dt = time.perf_counter() - t0
    print(f"\nrun_eval finished: rc={proc.returncode}, wall={dt:.1f}s")
    if proc.returncode != 0:
        print(f"FAIL — run_eval exited with non-zero code {proc.returncode}")
        return 2

    # Load output
    if not run_eval_output.exists():
        print(f"FAIL — expected output not found: {run_eval_output}")
        return 2
    with open(run_eval_output, encoding="utf-8") as f:
        data = json.load(f)
    records = data.get("records", [])
    if not records:
        print("FAIL — run_eval produced empty records")
        return 2
    if len(records) != 4:
        print(f"WARNING — expected 4 records, got {len(records)} (will continue check)")

    # Re-verify each chain (in case run_eval didn't, or to double-check)
    for r in records:
        ok, reason = reverify_chain(r.get("audit_log") or "")
        r["smoke_chain_recheck"] = {"ok": ok, "reason": reason}

    # Run acceptance
    print("\nAcceptance")
    print("-" * 78)
    overall, checks = check_acceptance(records, llm_ok, mock_dir_ok)
    for c in checks:
        marker = "✓" if c["pass"] else "✗"
        print(f"  [{c['id']}] {marker} {c['desc']}  ({c['detail']})")

    # Per-task summary
    print("\nPer-task results")
    print("-" * 78)
    print(f"  {'task':10s}  {'validity':22s}  {'calls':>6s}  {'denies':>7s}  {'chain':>6s}  {'attack_blocked':>15s}  {'completed':>10s}  err")
    for r in records:
        status = classify_validity(r)
        print(
            f"  {r['task_id']:10s}  {status:22s}  "
            f"{r.get('total_calls', 0):>6}  "
            f"{r.get('deny_count', 0):>7}  "
            f"{str(r.get('chain_valid', '?')):>6}  "
            f"{str(r.get('attack_blocked', '?')):>15}  "
            f"{str(r.get('task_completed', '?')):>10}  "
            f"{(r.get('error') or '')[:40]}"
        )

    # Write summary
    summary = {
        "protocol_version": read_protocol_version(),
        "task": "0.5a",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "backend": SMOKE_BACKEND,
        "model": SMOKE_MODEL,
        "samples": SMOKE_TASKS,
        "baseline": SMOKE_BASELINE,
        "run_eval_output": str(run_eval_output),
        "overall_pass": overall,
        "acceptance_checks": checks,
        "per_task_validity": [
            {
                "task_id": r["task_id"],
                "validity_status": classify_validity(r),
                "total_calls": r.get("total_calls", 0),
                "deny_count": r.get("deny_count", 0),
                "chain_valid": r.get("chain_valid"),
                "attack_blocked": r.get("attack_blocked"),
                "task_completed": r.get("task_completed"),
                "elapsed_s": r.get("elapsed_s"),
                "error": r.get("error"),
                "smoke_chain_recheck": r.get("smoke_chain_recheck"),
            }
            for r in records
        ],
        "n_records": len(records),
    }
    with open(summary_output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary written → {summary_output}")

    print("\n" + "=" * 78)
    print(f"Task 0.5a smoke test {'PASS' if overall else 'FAIL'}")
    print("=" * 78)
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
