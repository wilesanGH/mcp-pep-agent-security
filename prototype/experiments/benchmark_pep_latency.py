"""
experiments/benchmark_pep_latency.py — PEP Latency Micro-Benchmark.

Two-layer measurement:
  Layer 1  evaluate()        pure policy decision
                             (token check + DS detect on args + SI lookup + rule eval)
  Layer 2  intercept()       full enforcement path
                             (evaluate + record_high_risk + audit_log.log)
  Layer 2b intercept(ALLOW)  same + execute_allowed with mock tool
                             (isolates PEP labeling cost from real tool latency)

Scenarios:
  S1  short_path           {"path": "workspace/file.txt"}           typical read/write args
  S2  long_body_nohit      {"body": <1 KB clean text>}             worst-case DS scan, no hit
  S3  sensitive_args_hit   {"body": "API_KEY=sk-prod-abc123..."}   DS early-exit on hit
  S4  email_args_dict      {"to":..., "subject":..., "body":...}   multi-field args
  S5  result_label_1kb     mock tool returns 1 KB text              result DS labeling cost
  S6  result_label_4kb     mock tool returns 4 KB text              result DS labeling at scale

Adversarial pre-check:
  Runs DS detector on pathological strings before the main benchmark.
  If any pattern causes P99 > 5 ms, reports a warning and aborts.

Configuration: WARMUP = 100, RUNS = 5000
Reports: mean / P50 / P95 / P99 / max (microseconds)
"""

from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path

# ── path setup ──────────────────────────────────────────────────────────────
_PROTO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROTO_ROOT))

from datatypes import DS, SI, LabeledData, ToolCall, TraceState
from pep.capability_token import CapabilityToken
from pep.ds_detector import DSDetector
from pep.enforcer import PEPEnforcer
from pep.label_tracker import LabelTracker
from pep.rules import RuleEngine
from audit.logger import AuditLogger

# ── constants ────────────────────────────────────────────────────────────────
WARMUP = 100
RUNS   = 5000

# 1 KB / 4 KB clean text bodies (no DS-sensitive patterns)
_CLEAN_1KB = ("The quick brown fox jumps over the lazy dog. " * 23)[:1024]
_CLEAN_4KB = (_CLEAN_1KB * 4)[:4096]

# Sensitive body (API key, password)
_SENSITIVE_BODY = (
    "API_KEY=sk-prod-abc123secret\n"
    "DB_PASSWORD=hunter2\n"
    "JWT_SECRET=supersecretjwt\n"
)

# Email args dict (realistic multi-field call)
_EMAIL_ARGS = {
    "to":      "user@company.com",
    "subject": "Q1 2026 Report Summary",
    "body":    "Please find the quarterly revenue summary below.\n" + _CLEAN_1KB[:400],
}

# Adversarial inputs for regex stress test
_ADVERSARIAL = {
    "long_digits":        "4" * 200 + " " + "4" * 200,          # credit_card backtrack risk
    "long_digits_mixed":  "4 " * 200,                            # digits with spaces
    "long_bearer":        "Bearer " + "A" * 2048,                # bearer pattern
    "long_password":      "password=" + "x" * 2048,              # password pattern
    "long_jwt_like":      "eyJ" + "abcdefABCDEF0123456789" * 100, # jwt pattern
    "long_alphanumeric":  "aB3" * 500,                           # generic long string
    "long_path_like":     "/home/" + "a/b/" * 200,               # local_path pattern
}

ADVERSARIAL_WARN_US = 5_000   # warn if P99 > 5 ms on any adversarial input


# ── mock registry ────────────────────────────────────────────────────────────
class _MockRegistry:
    """Returns a fixed string for any tool call. Isolates PEP labeling cost."""
    def __init__(self, return_value: str = "mock result"):
        self._rv = return_value

    def execute(self, call: ToolCall) -> str:  # noqa: ARG002
        return self._rv


# ── timer ────────────────────────────────────────────────────────────────────
def _timeit(fn, warmup: int = WARMUP, runs: int = RUNS) -> list[int]:
    """Return sorted list of elapsed nanoseconds for `runs` calls to fn()."""
    for _ in range(warmup):
        fn()
    latencies: list[int] = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        latencies.append(time.perf_counter_ns() - t0)
    return sorted(latencies)


def _stats(ns: list[int], label: str) -> dict:
    n = len(ns)
    p = lambda pct: ns[int(n * pct / 100)] / 1_000  # → µs
    result = {
        "label":   label,
        "n":       n,
        "mean_us": round(statistics.mean(ns) / 1_000, 2),
        "p50_us":  round(p(50), 2),
        "p95_us":  round(p(95), 2),
        "p99_us":  round(p(99), 2),
        "max_us":  round(ns[-1] / 1_000, 2),
    }
    return result


# ── enforcer factory ─────────────────────────────────────────────────────────
def _make_enforcer(
    log_dir: str,
    mock_result: str = "mock result",
    ifc_enabled: bool = True,
    skip_pep: bool = False,
) -> tuple[PEPEnforcer, LabelTracker]:
    token   = CapabilityToken.for_attack(str(_PROTO_ROOT / "configs"))
    rules   = RuleEngine()
    tracker = LabelTracker(ifc_enabled=ifc_enabled)
    logger  = AuditLogger(log_dir=log_dir, session_id="bench")
    registry = _MockRegistry(mock_result)
    enforcer = PEPEnforcer(
        token=token,
        rule_engine=rules,
        label_tracker=tracker,
        audit_logger=logger,
        tool_registry=registry,
        skip_pep=skip_pep,
    )
    return enforcer, tracker


def _make_trace(tracker: LabelTracker, si: str = SI.MED) -> TraceState:
    state = tracker.init_trace(session_id="bench")
    state.current_si = si
    return state


def _make_call(tool: str, args: dict, trace_id: str, step: int = 0) -> ToolCall:
    return ToolCall(tool=tool, args=args, trace_id=trace_id, step=step)


# ── adversarial regex check ──────────────────────────────────────────────────
def run_adversarial_check() -> bool:
    """
    Test DS detector on pathological strings.
    Returns True (safe to continue) or False (abort).
    """
    print("=" * 70)
    print("ADVERSARIAL REGEX PRE-CHECK")
    print("=" * 70)
    ds = DSDetector()
    ok = True
    for name, text in _ADVERSARIAL.items():
        ns = _timeit(lambda t=text: ds.detect(t), warmup=20, runs=500)
        s = _stats(ns, name)
        flag = "⚠️  WARN" if s["p99_us"] > ADVERSARIAL_WARN_US else "✅ OK "
        print(f"  {flag}  {name:<28s}  P50={s['p50_us']:>8.1f} µs  "
              f"P95={s['p95_us']:>8.1f} µs  P99={s['p99_us']:>8.1f} µs")
        if s["p99_us"] > ADVERSARIAL_WARN_US:
            ok = False
    print()
    return ok


# ── main benchmark ────────────────────────────────────────────────────────────
def run_benchmark() -> list[dict]:
    results: list[dict] = []

    print("=" * 70)
    print(f"PEP LATENCY BENCHMARK   (warmup={WARMUP}, runs={RUNS})")
    print("=" * 70)

    # ── Scenario definitions ─────────────────────────────────────────────────
    # (tool, args, SI for the trace at call time, expected_decision_label)
    SCENARIOS = [
        ("S1  short_path",
         "filesystem.read_file", {"path": "workspace/file.txt"}, SI.MED, "ALLOW"),
        ("S2  long_body_nohit",
         "filesystem.write_file", {"path": "workspace/out.txt", "content": _CLEAN_1KB},
         SI.MED, "ALLOW"),
        ("S3  sensitive_args_hit",
         "filesystem.write_file",
         {"path": "workspace/out.txt", "content": _SENSITIVE_BODY},
         SI.MED, "ALLOW"),   # ALLOW: write_file not in R02 watch list; DS:SENSITIVE flagged but no DENY
        ("S4  email_dict",
         "send_email.send", _EMAIL_ARGS, SI.MED, "DENY-R02"),   # DS:SENSITIVE → R02
        ("S1d short_path_deny [R01]",
         "shell.run", {"command": "ls workspace/"}, SI.LOW, "DENY-R01"),
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        for label, tool, args, si_level, exp in SCENARIOS:
            # ── fresh enforcer per scenario (avoids token call-count saturation)
            enf, tracker = _make_enforcer(tmpdir)
            state = _make_trace(tracker, si=si_level)
            tid   = state.trace_id
            call  = _make_call(tool, args, tid)

            # ─── Layer 1: evaluate() only ────────────────────────────────────
            ns = _timeit(lambda: enf.evaluate(call, state))
            s = _stats(ns, f"{label} | evaluate()")
            results.append(s)
            _print_row(s)

            # ─── Layer 2: intercept() full path ──────────────────────────────
            # Re-create per intercept to keep trace state clean & audit file small
            # (avoids high_risk_call_timestamps O(n) accumulation for R05)
            def _intercept_fn(t=tool, a=args, si=si_level):
                _enf, _tr = _make_enforcer(tmpdir)
                _st = _make_trace(_tr, si=si)
                _c  = _make_call(t, a, _st.trace_id)
                _enf.intercept(_c, _st)

            ns2 = _timeit(_intercept_fn)
            s2  = _stats(ns2, f"{label} | intercept()")
            results.append(s2)
            _print_row(s2)

            print()

        # ── S5/S6: result labeling (execute_allowed with mock, varying output) ──
        print("─" * 70)
        print("Result labeling overhead (execute_allowed with mock tool)")
        print("─" * 70)
        for size_label, mock_output in [("S5  result_1kb", _CLEAN_1KB),
                                        ("S6  result_4kb", _CLEAN_4KB)]:
            def _label_fn(output=mock_output):
                _enf, _tr = _make_enforcer(tmpdir, mock_result=output)
                _st = _make_trace(_tr, si=SI.LOW)
                # Use filesystem.read_file which always ALLOWs, so execute_allowed runs
                _c = _make_call("filesystem.read_file",
                                {"path": "workspace/file.txt"}, _st.trace_id)
                _enf.execute_allowed(_c)

            ns = _timeit(_label_fn)
            s  = _stats(ns, f"{size_label} | execute_allowed(mock)")
            results.append(s)
            _print_row(s)
        print()

        # ── Audit log write isolated ──────────────────────────────────────────
        print("─" * 70)
        print("Audit log write isolated (logger.log() only, ALLOW event)")
        print("─" * 70)
        _enf_log, _tr_log = _make_enforcer(tmpdir)
        _st_log = _make_trace(_tr_log)
        _c_log  = _make_call("filesystem.read_file",
                              {"path": "workspace/file.txt"}, _st_log.trace_id)
        from datatypes import PolicyDecision
        _allow_dec = PolicyDecision(
            action="ALLOW", matched_rule=None,
            reason="bench", evaluated_si=SI.MED, evaluated_ds=DS.NORMAL,
        )
        ns = _timeit(lambda: _enf_log._logger.log(_c_log, _allow_dec, _st_log))
        s  = _stats(ns, "audit_log.log() — ALLOW event")
        results.append(s)
        _print_row(s)
        print()

    return results


def _print_row(s: dict) -> None:
    print(f"  {s['label']:<55s}  "
          f"mean={s['mean_us']:>7.1f}µs  "
          f"P50={s['p50_us']:>7.1f}µs  "
          f"P95={s['p95_us']:>7.1f}µs  "
          f"P99={s['p99_us']:>7.1f}µs  "
          f"max={s['max_us']:>8.1f}µs")


# ── output ────────────────────────────────────────────────────────────────────
def save_results(results: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "benchmark": "pep_latency",
            "warmup": WARMUP,
            "runs":   RUNS,
            "results": results,
        }, f, indent=2)
    print(f"Results saved to: {out_path}")


# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    safe = run_adversarial_check()
    if not safe:
        print("⚠️  One or more adversarial inputs exceeded the 5 ms P99 threshold.")
        print("    Fix the problematic regex pattern before reporting latency numbers.")
        print("    Continuing benchmark anyway (results may be inflated by backtracking).")
        print()

    results = run_benchmark()

    out = _PROTO_ROOT / "results" / "metrics" / "benchmark_pep_latency.json"
    save_results(results, out)

    # ── summary for paper ────────────────────────────────────────────────────
    print("=" * 70)
    print("PAPER-READY SUMMARY")
    print("=" * 70)
    # Find evaluate() and intercept() for the "normal" scenario (S1)
    for s in results:
        if "S1  short_path" in s["label"] or "result_label" in s["label"] or "audit_log" in s["label"]:
            print(f"  {s['label']:<55s}  P50={s['p50_us']:>6.1f}µs  P95={s['p95_us']:>6.1f}µs")
