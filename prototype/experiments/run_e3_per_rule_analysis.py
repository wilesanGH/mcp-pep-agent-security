"""
experiments/run_e3_per_rule_analysis.py — E3: consolidated per-rule analysis.

R1/R2/R3 major-revision experiment E3. Post-processes EXISTING cross-model audit
logs (no new runs) to produce the per-rule firing distribution that reviewers
requested, with DENY and REQUIRE_CONFIRM counted SEPARATELY and labelled as
FIRST-MATCHED-RULE counts (audit records expose only the first matching rule).

Critically, this REPLACES the unverified "Qwen FPR is R04" hypothesis with the
ACTUAL observed first-matched-rule distribution on benign (N) tasks under the
full system (baseline D) per model.

Outputs (results/metrics/e3_per_rule.json + printed tables):
  X1  first-matched-rule x attack class x model (DENY/CONFIRM separated)
  X3  benign first-matched-rule x model (the corrected cross-model FPR root cause)

Usage:
  python experiments/run_e3_per_rule_analysis.py
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict, Counter
from pathlib import Path

_PROTO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROTO_ROOT))

# Canonical per-model metrics files (full MVP-30 / cross-model phase-2 runs).
_MODEL_METRICS = {
    "deepseek-v4-pro": "results_jisa_v8/metrics/phase2_main_deepseek-v4-pro_mvp30_v8.5.3.json",
    "deepseek-chat":   "results_jisa_v8/metrics/phase2_cross_version_deepseek-chat_mvp30_v8.5.3.json",
    "qwen3.5-plus":    "results_jisa_v8/qwen_replication/metrics/phase2_replication_qwen3.5-plus_mvp30_v8.5.3.json",
    "glm-4.7":         "results_jisa_v8/phase4_cross_model/glm-4.7/metrics/eval_llm_glm-4_7_20260507_132533.json",
    "claude-haiku-4.5":"results_jisa_v8/phase4_cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_20260507_173424.json",
    "kimi-k2.5":       "results_jisa_v8/phase4_cross_model/kimi-k2.5/metrics/eval_llm_kimi-k2_5_20260507_140421.json",
    "llama-3.3-70b":   "results_jisa_v8/phase4_cross_model/llama-3.3-70b/metrics/eval_llm_meta-llama_llama-3_3-70b-instruct_20260507_170432.json",
}

_BASELINE = "full"  # baseline D


def _resolve_audit(path: str) -> Path | None:
    p = Path(path)
    if p.exists():
        return p
    rebased = _PROTO_ROOT / path
    return rebased if rebased.exists() else None


def _first_rule_events(audit_path: Path) -> list[tuple[str, str]]:
    """Return [(decision, matched_rule)] for non-ALLOW events in a trace log."""
    out = []
    try:
        for line in open(audit_path, encoding="utf-8"):
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            dec = ev.get("policy_decision", "")
            rule = ev.get("matched_rule", "") or "(none)"
            if dec in ("DENY", "REQUIRE_CONFIRM"):
                out.append((dec, rule))
    except OSError:
        pass
    return out


def analyse():
    # X1: attack class -> model -> {DENY: Counter(rule), CONFIRM: Counter(rule)}
    # X3: benign      -> model -> {DENY: Counter(rule), CONFIRM: Counter(rule)}
    x1 = defaultdict(lambda: defaultdict(lambda: {"DENY": Counter(), "CONFIRM": Counter()}))
    x3 = defaultdict(lambda: {"DENY": Counter(), "CONFIRM": Counter()})
    coverage = {}

    for model, mf in _MODEL_METRICS.items():
        mfp = _PROTO_ROOT / mf
        if not mfp.exists():
            coverage[model] = "metrics file missing"
            continue
        recs = json.load(open(mfp, encoding="utf-8")).get("records", [])
        recs = [r for r in recs if r.get("baseline") == _BASELINE]
        coverage[model] = f"{len(recs)} full-baseline records"
        for r in recs:
            ap = _resolve_audit(r.get("audit_log", ""))
            if ap is None:
                continue
            events = _first_rule_events(ap)
            ttype = r.get("task_type", "")
            aclass = r.get("attack_type") or "N"  # benign tasks: attack_type None -> 'N'
            for dec, rule in events:
                key = "DENY" if dec == "DENY" else "CONFIRM"
                if ttype == "attack":
                    x1[aclass][model][key][rule] += 1
                else:
                    x3[model][key][rule] += 1
    return x1, x3, coverage


def _fmt_counter(c: Counter) -> str:
    if not c:
        return "-"
    return ", ".join(f"{k}:{v}" for k, v in sorted(c.items(), key=lambda kv: -kv[1]))


def main():
    x1, x3, coverage = analyse()

    print("=" * 78)
    print("E3 — Consolidated First-Matched-Rule Analysis (baseline D, existing logs)")
    print("=" * 78)
    print("\nCoverage:")
    for m, c in coverage.items():
        print(f"  {m:18} {c}")

    print("\n--- X3: BENIGN first-matched-rule by model (the FPR root cause) ---")
    print(f"{'model':18} {'DENY rules':40} {'CONFIRM rules'}")
    for model in _MODEL_METRICS:
        if model in x3:
            d = _fmt_counter(x3[model]["DENY"])
            c = _fmt_counter(x3[model]["CONFIRM"])
            print(f"{model:18} {d:40} {c}")

    print("\n--- X1: ATTACK first-matched-rule by class x model ---")
    for aclass in sorted(x1):
        print(f"\n  [{aclass}]")
        print(f"  {'model':18} {'DENY rules':40} {'CONFIRM rules'}")
        for model in _MODEL_METRICS:
            if model in x1[aclass]:
                d = _fmt_counter(x1[aclass][model]["DENY"])
                c = _fmt_counter(x1[aclass][model]["CONFIRM"])
                print(f"  {model:18} {d:40} {c}")

    # Serialize
    def _ser(counter_pair):
        return {k: dict(v) for k, v in counter_pair.items()}
    out = {
        "baseline": _BASELINE,
        "coverage": coverage,
        "X3_benign_by_model": {m: _ser(x3[m]) for m in x3},
        "X1_attack_by_class_model": {
            ac: {m: _ser(x1[ac][m]) for m in x1[ac]} for ac in x1
        },
    }
    out_path = _PROTO_ROOT / "results" / "metrics" / "e3_per_rule.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
