"""
tests/test_stats_aggregation.py — JISA v8 Task 1.5

Unit tests for experiments.stats:
  * _per_repeat_metrics — single-repeat metric extraction
  * aggregate_records   — cross-repeat mean/std with validity exclusion
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

PROTO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTO_ROOT))

from experiments.stats import (  # noqa: E402
    _per_repeat_metrics,
    aggregate_records,
    _mean_std,
)


# ---------------------------------------------------------------------------
# Builders for synthetic records
# ---------------------------------------------------------------------------

def _attack(*, baseline: str = "full", repeat_id: int = 0,
            blocked: bool = True, mpa=False, attempted=True,
            hr_total: int = 1, hr_allowed: int = 0,
            error: str = "") -> dict:
    return {
        "task_id": f"T1-x{repeat_id}",
        "task_type": "attack",
        "baseline": baseline,
        "repeat_id": repeat_id,
        "attack_blocked": blocked,
        "malicious_payload_attempted": mpa,
        "llm_attempted_attack": attempted,
        "task_completed": True,
        "total_calls": 1,
        "deny_count": 1 if blocked and mpa else 0,
        "hr_total": hr_total,
        "hr_allowed": hr_allowed,
        "error": error,
    }


def _normal(*, baseline: str = "full", repeat_id: int = 0,
            done: bool = True, denies: int = 0, total_calls: int = 2,
            error: str = "") -> dict:
    return {
        "task_id": f"N-x{repeat_id}",
        "task_type": "normal",
        "baseline": baseline,
        "repeat_id": repeat_id,
        "attack_blocked": True,
        "malicious_payload_attempted": None,
        "llm_attempted_attack": None,
        "task_completed": done,
        "total_calls": total_calls,
        "deny_count": denies,
        "hr_total": 0,
        "hr_allowed": 0,
        "error": error,
    }


# ---------------------------------------------------------------------------
# _mean_std
# ---------------------------------------------------------------------------

def test_mean_std_single_value_has_no_std() -> None:
    out = _mean_std([0.5])
    assert out["mean"] == 0.5
    assert out["std"] is None
    assert out["n"] == 1


def test_mean_std_uses_sample_std_ddof1() -> None:
    out = _mean_std([0.0, 1.0])
    assert out["mean"] == 0.5
    # ddof=1 std of [0, 1] = sqrt(((0-0.5)^2 + (1-0.5)^2) / (2-1)) = sqrt(0.5)
    assert out["std"] is not None
    assert math.isclose(out["std"], math.sqrt(0.5), rel_tol=1e-3)
    assert out["n"] == 2


def test_mean_std_empty_input() -> None:
    out = _mean_std([])
    assert out == {"mean": None, "std": None, "n": 0}


# ---------------------------------------------------------------------------
# _per_repeat_metrics
# ---------------------------------------------------------------------------

def test_per_repeat_asr_with_one_succeeded_one_blocked() -> None:
    recs = [
        _attack(blocked=False, mpa=True),  # succeeded
        _attack(blocked=True,  mpa=True),  # blocked
    ]
    m = _per_repeat_metrics(recs)
    assert m["ASR"] == 0.5


def test_per_repeat_tsr_uses_normal_only() -> None:
    recs = [
        _attack(blocked=True, mpa=True),         # ignored for TSR
        _normal(done=True),
        _normal(done=False),
    ]
    m = _per_repeat_metrics(recs)
    assert m["TSR"] == 0.5


def test_per_repeat_fpr_call_uses_normal_calls_only() -> None:
    """FPR_call denominator must include only normal-task calls; attack-task
    denies are not false positives even if they DENY benign-looking content."""
    recs = [
        _normal(total_calls=4, denies=1),  # 1/4 denied in normal
        _attack(blocked=True, mpa=True),   # attack deny — not counted
    ]
    m = _per_repeat_metrics(recs)
    assert m["FPR_call"] == 0.25


def test_per_repeat_fnr_call_uses_attack_high_risk_only() -> None:
    recs = [
        _attack(hr_total=2, hr_allowed=1),
        _attack(hr_total=2, hr_allowed=0),
        _normal(),
    ]
    m = _per_repeat_metrics(recs)
    # FNR = hr_allowed/hr_total summed across attacks = 1 / 4
    assert m["FNR_call"] == 0.25


def test_per_repeat_attempt_and_mpa_rates() -> None:
    recs = [
        _attack(attempted=True,  mpa=True),
        _attack(attempted=True,  mpa=False),
        _attack(attempted=False, mpa=False),
    ]
    m = _per_repeat_metrics(recs)
    assert m["attack_attempt_rate"] == 2 / 3
    assert m["malicious_payload_rate"] == 1 / 3


def test_per_repeat_excludes_invalid_records() -> None:
    """HARNESS_ERROR / PROVIDER_ERROR records must not enter metric computation."""
    recs = [
        _attack(blocked=True, mpa=True),                       # valid
        _attack(blocked=False, mpa=True, error="HTTP 503"),    # provider — exclude
        _attack(blocked=False, mpa=True, error="AssertionError"),  # harness — exclude
    ]
    m = _per_repeat_metrics(recs)
    # Only the first record counts — ASR = 0/1 = 0
    assert m["ASR"] == 0.0


def test_per_repeat_no_attacks_returns_none_for_attack_metrics() -> None:
    recs = [_normal(done=True), _normal(done=False)]
    m = _per_repeat_metrics(recs)
    assert m["ASR"] is None
    assert m["FNR_call"] is None
    assert m["TSR"] == 0.5


# ---------------------------------------------------------------------------
# aggregate_records — full pipeline
# ---------------------------------------------------------------------------

def test_aggregate_groups_by_repeat_then_means_across() -> None:
    """Three repeats of (1 attack blocked, 1 attack succeeded) under 'full':
    each repeat's ASR = 0.5, mean=0.5, std=0."""
    recs = []
    for rep in range(3):
        recs.append(_attack(repeat_id=rep, blocked=True,  mpa=True))
        recs.append(_attack(repeat_id=rep, blocked=False, mpa=True))

    summary = aggregate_records(recs)
    full = summary["per_baseline"]["full"]
    assert full["n_repeats"] == 3
    assert full["repeat_ids"] == [0, 1, 2]
    asr = full["metrics"]["ASR"]
    assert asr["mean"] == 0.5
    assert asr["std"] == 0.0
    assert asr["n"] == 3


def test_aggregate_handles_uneven_repeat_metrics() -> None:
    """Repeat 0 has attacks (ASR computable); repeat 1 has only normals
    (ASR = None). Mean over per-repeat ASRs should ignore None."""
    recs = [
        _attack(repeat_id=0, blocked=True,  mpa=True),
        _attack(repeat_id=0, blocked=False, mpa=True),
        _normal(repeat_id=1, done=True),
        _normal(repeat_id=1, done=False),
    ]
    summary = aggregate_records(recs)
    full = summary["per_baseline"]["full"]
    asr = full["metrics"]["ASR"]
    assert asr["n"] == 1            # only repeat 0 yielded an ASR
    assert asr["mean"] == 0.5
    tsr = full["metrics"]["TSR"]
    assert tsr["n"] == 1            # only repeat 1 yielded a TSR
    assert tsr["mean"] == 0.5


def test_aggregate_validity_counts_include_invalid_records() -> None:
    recs = [
        _attack(blocked=True,  mpa=True),
        _attack(blocked=False, mpa=True, error="HTTP 503"),
        _attack(blocked=False, mpa=True, error="AssertionError"),
    ]
    summary = aggregate_records(recs)
    bl = summary["per_baseline"]["full"]
    assert bl["n_runs_total"] == 3
    assert bl["n_runs_valid"] == 1
    assert bl["n_provider_error"] == 1
    assert bl["n_harness_error"] == 1
    assert math.isclose(bl["provider_error_rate"], 1 / 3, rel_tol=1e-3)


def test_aggregate_security_outcome_counts() -> None:
    recs = [
        _attack(blocked=True,  mpa=True),    # POLICY_DENIED (deny_count=1 from builder)
        _attack(blocked=True,  mpa=False),   # SELF_SANITIZED
        _attack(blocked=True,  mpa=False),   # SELF_SANITIZED
        _attack(blocked=False, mpa=True),    # ATTACK_SUCCEEDED
        _normal(done=True),                  # not counted (benign)
    ]
    summary = aggregate_records(recs)
    counts = summary["per_baseline"]["full"]["security_outcome_counts"]
    assert counts.get("POLICY_DENIED")    == 1
    assert counts.get("SELF_SANITIZED")   == 2
    assert counts.get("ATTACK_SUCCEEDED") == 1


def test_aggregate_blocked_other_separated_from_policy_denied() -> None:
    """v8.4.1 P2 fix: when an attack is blocked AND the model issued the
    payload BUT no DENY was recorded, the outcome is BLOCKED_OTHER, not
    POLICY_DENIED. The aggregator must count those buckets separately so
    Phase 2 reports do not over-credit the policy."""
    # Manually craft records: payload issued, no deny, still blocked.
    rec_blocked_other = {
        "task_id": "T1-x", "task_type": "attack",
        "baseline": "full", "repeat_id": 0,
        "attack_blocked": True,
        "malicious_payload_attempted": True,
        "llm_attempted_attack": True,
        "task_completed": True,
        "total_calls": 1, "deny_count": 0,
        "hr_total": 1, "hr_allowed": 1,
        "error": "",
    }
    rec_policy_denied = {
        **rec_blocked_other, "task_id": "T1-y",
        "deny_count": 1,
    }
    summary = aggregate_records([rec_blocked_other, rec_policy_denied])
    counts = summary["per_baseline"]["full"]["security_outcome_counts"]
    assert counts.get("BLOCKED_OTHER")  == 1
    assert counts.get("POLICY_DENIED")  == 1
    assert "POLICY_DENIED" in counts and "BLOCKED_OTHER" in counts


def test_aggregate_multiple_baselines_kept_separate() -> None:
    recs = [
        _attack(baseline="no_defense", blocked=False, mpa=True),
        _attack(baseline="no_defense", blocked=False, mpa=True),
        _attack(baseline="full",       blocked=True,  mpa=True),
        _attack(baseline="full",       blocked=True,  mpa=True),
    ]
    summary = aggregate_records(recs)
    assert summary["per_baseline"]["no_defense"]["metrics"]["ASR"]["mean"] == 1.0
    assert summary["per_baseline"]["full"]["metrics"]["ASR"]["mean"]       == 0.0


def test_aggregate_respects_baseline_ordering() -> None:
    """Caller can supply explicit baseline order; aggregator should preserve it."""
    recs = [
        _attack(baseline="full",       blocked=True),
        _attack(baseline="no_defense", blocked=False),
    ]
    summary = aggregate_records(recs, baselines=["no_defense", "full"])
    assert list(summary["per_baseline"].keys()) == ["no_defense", "full"]


def test_empty_input_returns_empty_summary() -> None:
    summary = aggregate_records([])
    assert summary["per_baseline"] == {}
    assert summary["n_records"] == 0
    assert summary["baselines"] == []
