"""
experiments/stats.py — JISA v8 Task 1.5

Cross-repeat statistical aggregation for run records produced by run_eval.py
with `--repeats N`.

Inputs
------
A list of run records (or a path to one or more eval JSONs). Each record must
carry the v8.3.x Task 1.5 schema fields:

  required:  task_id, task_type, baseline, repeat_id
  for stats: total_calls, deny_count, hr_total, hr_allowed,
             attack_blocked, task_completed,
             llm_attempted_attack, malicious_payload_attempted,
             validity_status, security_outcome

Outputs
-------
A structured `stats_summary` dict with one entry per baseline holding:

  metrics:
    ASR  (mean ± std across repeats, task-level: attacks not blocked / attacks)
    TSR  (mean ± std, task-level: normals completed / normals)
    FPR_call  (call-level: deny / total in normal tasks; per-repeat aggregated)
    FPR_task  (task-level: any-deny in normal tasks)
    FNR_call  (call-level: hr_allowed / hr_total in attack tasks)
    attack_attempt_rate         (fraction of attack tasks where llm_attempted_attack=True)
    malicious_payload_rate      (fraction where mpa=True)

  validity counts (HARNESS_ERROR / PROVIDER_ERROR / VALID_*)
  security_outcome counts (POLICY_DENIED / SELF_SANITIZED / ATTACK_SUCCEEDED)

Each metric is computed *once per repeat* on that repeat's slice of records,
then mean/std are computed across the per-repeat values. This matches the
"5-repeat" protocol in §6 — one ASR per repeat, then mean ± std across them.

Invalid records (HARNESS_ERROR / PROVIDER_ERROR) are excluded from metric
computation but counted in the validity table for transparency.
"""
from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

# Make sure run_eval and validity helpers are importable when stats is run as a script
import sys as _sys
_PROTO_ROOT = Path(__file__).resolve().parent.parent
if str(_PROTO_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PROTO_ROOT))

from experiments.validity import classify_validity, classify_security_outcome  # noqa: E402


# ---------------------------------------------------------------------------
# Mean / std helpers (no numpy dependency)
# ---------------------------------------------------------------------------

def _mean_std(values: list[float]) -> dict:
    """Sample mean & sample std (ddof=1). Returns {mean, std, n}.

    Sample std (ddof=1) is what you want when reporting "mean ± std" across a
    finite number of repeats — that's the unbiased estimator of the population
    sigma, and it's the convention in the experimental protocol §6.
    """
    if not values:
        return {"mean": None, "std": None, "n": 0}
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return {"mean": round(mean, 4), "std": None, "n": n}
    var = sum((v - mean) ** 2 for v in values) / (n - 1)
    return {"mean": round(mean, 4), "std": round(math.sqrt(var), 4), "n": n}


# ---------------------------------------------------------------------------
# Per-repeat metric extraction
# ---------------------------------------------------------------------------

def _records_for_repeat(records: list[dict], baseline: str, repeat_id: int) -> list[dict]:
    return [r for r in records if r.get("baseline") == baseline and r.get("repeat_id") == repeat_id]


def _per_repeat_metrics(records_one_repeat: list[dict]) -> dict:
    """Compute the seven scalar metrics for a single repeat slice.

    Records that classify as HARNESS_ERROR / PROVIDER_ERROR are excluded from
    metric numerators/denominators but still counted in validity tallies.
    """
    valid = [r for r in records_one_repeat if classify_validity(r) not in ("HARNESS_ERROR", "PROVIDER_ERROR")]
    attacks = [r for r in valid if r.get("task_type") == "attack"]
    normals = [r for r in valid if r.get("task_type") == "normal"]

    n_attack = len(attacks)
    n_normal = len(normals)

    asr = (sum(1 for r in attacks if not r.get("attack_blocked", True)) / n_attack) if n_attack else None
    tsr = (sum(1 for r in normals if r.get("task_completed", False)) / n_normal) if n_normal else None

    normal_total_calls  = sum((r.get("total_calls", 0) or 0) for r in normals)
    normal_denied_calls = sum((r.get("deny_count",  0) or 0) for r in normals)
    fpr_call = (normal_denied_calls / normal_total_calls) if normal_total_calls > 0 else None
    fpr_task = (sum(1 for r in normals if (r.get("deny_count", 0) or 0) > 0) / n_normal) if n_normal else None

    hr_total   = sum((r.get("hr_total",   0) or 0) for r in attacks)
    hr_allowed = sum((r.get("hr_allowed", 0) or 0) for r in attacks)
    fnr_call = (hr_allowed / hr_total) if hr_total > 0 else None

    attempts = [r for r in attacks if r.get("llm_attempted_attack") is not None]
    attack_attempt_rate = (
        sum(1 for r in attempts if r.get("llm_attempted_attack")) / len(attempts)
        if attempts else None
    )

    mpa_eligible = [r for r in attacks if r.get("malicious_payload_attempted") is not None]
    malicious_payload_rate = (
        sum(1 for r in mpa_eligible if r.get("malicious_payload_attempted")) / len(mpa_eligible)
        if mpa_eligible else None
    )

    return {
        "ASR": asr,
        "TSR": tsr,
        "FPR_call": fpr_call,
        "FPR_task": fpr_task,
        "FNR_call": fnr_call,
        "attack_attempt_rate": attack_attempt_rate,
        "malicious_payload_rate": malicious_payload_rate,
    }


# ---------------------------------------------------------------------------
# Per-baseline aggregation
# ---------------------------------------------------------------------------

_METRIC_KEYS = (
    "ASR", "TSR", "FPR_call", "FPR_task", "FNR_call",
    "attack_attempt_rate", "malicious_payload_rate",
)


def _aggregate_one_baseline(records: list[dict], baseline: str) -> dict:
    bl_records = [r for r in records if r.get("baseline") == baseline]
    if not bl_records:
        return {"n_runs_total": 0}

    repeat_ids = sorted({r.get("repeat_id", 0) for r in bl_records})

    # Per-repeat metric vectors
    per_repeat: list[dict] = []
    for rep in repeat_ids:
        slice_ = _records_for_repeat(bl_records, baseline, rep)
        per_repeat.append(_per_repeat_metrics(slice_))

    metrics_agg: dict[str, dict] = {}
    for key in _METRIC_KEYS:
        values = [m[key] for m in per_repeat if m[key] is not None]
        metrics_agg[key] = _mean_std(values)

    # Validity tallies (counted across all records, including invalid)
    val_counts: Counter[str] = Counter(classify_validity(r) for r in bl_records)
    sec_counts: Counter[str] = Counter(
        classify_security_outcome(r)
        for r in bl_records
        if r.get("task_type") == "attack"
    )

    n_total = len(bl_records)
    n_invalid = val_counts.get("HARNESS_ERROR", 0) + val_counts.get("PROVIDER_ERROR", 0)
    n_valid = n_total - n_invalid

    return {
        "n_runs_total":       n_total,
        "n_runs_valid":       n_valid,
        "n_harness_error":    val_counts.get("HARNESS_ERROR", 0),
        "n_provider_error":   val_counts.get("PROVIDER_ERROR", 0),
        "harness_error_rate": round(val_counts.get("HARNESS_ERROR", 0) / n_total, 4) if n_total else None,
        "provider_error_rate": round(val_counts.get("PROVIDER_ERROR", 0) / n_total, 4) if n_total else None,
        "n_repeats":          len(repeat_ids),
        "repeat_ids":         repeat_ids,
        "metrics":            metrics_agg,
        "validity_counts":    dict(val_counts),
        "security_outcome_counts": dict(sec_counts),
    }


# ---------------------------------------------------------------------------
# Top-level entry points
# ---------------------------------------------------------------------------

def aggregate_records(
    records: list[dict],
    baselines: Optional[Iterable[str]] = None,
    meta: Optional[dict] = None,
) -> dict:
    """Aggregate a flat list of records into a stats summary dict.

    `baselines` defaults to the union of baselines observed in `records`,
    sorted alphabetically. Pass an explicit ordering to keep §4 tables
    consistent across multiple aggregation runs.
    """
    if baselines is None:
        baselines = sorted({r.get("baseline", "?") for r in records})
    per_baseline = {bl: _aggregate_one_baseline(records, bl) for bl in baselines}
    return {
        "meta": meta or {},
        "per_baseline": per_baseline,
        "n_records":    len(records),
        "baselines":    list(baselines),
    }


def aggregate_files(
    paths: Iterable[str | Path],
    baselines: Optional[Iterable[str]] = None,
) -> dict:
    """Load one or more eval JSONs (each with `records`) and aggregate."""
    records: list[dict] = []
    metas: list[dict] = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if "records" in data:
            records.extend(data["records"])
        if "meta" in data:
            metas.append(data["meta"])
    merged_meta = {
        "source_files": [str(p) for p in paths],
        "n_source_files": len(metas),
    }
    if metas:
        merged_meta["first_source_meta"] = metas[0]
    return aggregate_records(records, baselines=baselines, meta=merged_meta)


# ---------------------------------------------------------------------------
# CLI: aggregate one-or-more eval JSONs and write summary to stats/
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    from datetime import datetime, timezone

    p = argparse.ArgumentParser(description="Aggregate run_eval.py outputs across repeats.")
    p.add_argument("paths", nargs="+", help="Eval JSON file(s) (each has `records`)")
    p.add_argument(
        "--results-dir", default=None,
        help="Stats output root (default: same as first input file's parent's parent / 'stats')",
    )
    p.add_argument("--out", default=None, help="Override output path")
    p.add_argument("--baselines", nargs="*", default=None, help="Restrict / order baselines")
    args = p.parse_args()

    summary = aggregate_files(args.paths, baselines=args.baselines)

    if args.out:
        out_path = Path(args.out)
    else:
        # Default: <first_input>.parent.parent / stats / stats_<timestamp>.json
        first = Path(args.paths[0])
        if args.results_dir:
            stats_dir = Path(args.results_dir) / "stats"
        else:
            stats_dir = first.parent.parent / "stats"
        stats_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        out_path = stats_dir / f"stats_{ts}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"stats summary → {out_path}")

    # Brief stdout table
    print()
    print(f"{'baseline':18s}  {'ASR':>10s}  {'TSR':>10s}  {'FPR_c':>10s}  {'FNR_c':>10s}  {'mpa':>10s}  n_valid")
    print("-" * 90)
    for bl, agg in summary["per_baseline"].items():
        m = agg.get("metrics", {})
        def fmt(k: str) -> str:
            d = m.get(k, {})
            mu, sd = d.get("mean"), d.get("std")
            if mu is None:
                return "    n/a   "
            if sd is None:
                return f"  {mu:.3f}    "
            return f"{mu:.3f}±{sd:.3f}"
        print(
            f"{bl:18s}  {fmt('ASR'):>10s}  {fmt('TSR'):>10s}  "
            f"{fmt('FPR_call'):>10s}  {fmt('FNR_call'):>10s}  "
            f"{fmt('malicious_payload_rate'):>10s}  {agg.get('n_runs_valid', 0)}/{agg.get('n_runs_total', 0)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
