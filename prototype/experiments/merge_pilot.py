"""
merge_pilot.py — Merge main + supplementary AgentDojo pilot results.

Combines:
  A:     pilot_workspace_no_defense_r5_20260506_061210.jsonl  (main, 7 user × 5 inj × 5 rep = 175 attack)
       + pilot_workspace_no_defense_r5_20260506_095232.jsonl  (suppl, 3 user × 5 inj × 5 rep = 75 attack)
  B-enc: pilot_workspace_prompt_enc_r5_20260506_070441.jsonl  (main)
       + pilot_workspace_prompt_enc_r5_20260506_103528.jsonl  (suppl)
  D:     pilot_workspace_full_r5_20260506_090205.jsonl        (already 50 unique pairs in main)

Outputs:
  merged_workspace_<baseline>_r5_<ts>.jsonl + _metrics.json
"""

from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).parent
_PROTO = _HERE.parent
sys.path.insert(0, str(_PROTO))

from experiments.run_agentdojo import compute_metrics

DIR = _PROTO / "results_jisa_v8/agentdojo/workspace"

MERGE_PLAN = {
    "no_defense": [
        DIR / "pilot_workspace_no_defense_r5_20260506_061210.jsonl",  # main 35 unique × 5
        DIR / "pilot_workspace_no_defense_r5_20260506_095232.jsonl",  # suppl 15 unique × 5
    ],
    "prompt_enc": [
        DIR / "pilot_workspace_prompt_enc_r5_20260506_070441.jsonl",
        DIR / "pilot_workspace_prompt_enc_r5_20260506_103528.jsonl",
    ],
    "full": [
        DIR / "pilot_workspace_full_r5_20260506_090205.jsonl",  # already 50 unique × 5
    ],
}


def merge_baseline(baseline: str, source_files: list[Path]) -> tuple[Path, dict]:
    """
    Merge attack rows from all source files but keep benign rows only from
    the FIRST source (main pilot). Without this de-dup, A/B-enc would have
    20 benign runs while D has 10, mismatching the TSR denominator.

    Resulting shape per baseline: 250 attack + 10 benign = 260 rows.
    """
    rows: list[dict] = []
    for idx, f in enumerate(source_files):
        is_first = (idx == 0)
        with open(f, encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                # Keep all rows from the first source; from supplementary
                # sources keep ONLY attack pairs (drop duplicate benigns).
                if is_first or r.get("injected"):
                    rows.append(r)
    metrics = compute_metrics(rows)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = f"merged_workspace_{baseline}_r5_{ts}"
    out_jsonl = DIR / f"{stem}.jsonl"
    out_metrics = DIR / f"{stem}_metrics.json"
    with open(out_jsonl, "w", encoding="utf-8") as fp:
        for r in rows:
            fp.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(out_metrics, "w", encoding="utf-8") as fp:
        json.dump({
            "tag": f"merged_workspace_{baseline}_r5",
            "timestamp": ts,
            "source_files": [str(s.name) for s in source_files],
            "metrics": metrics,
            "n_runs": len(rows),
        }, fp, indent=2, ensure_ascii=False)
    return out_jsonl, metrics


def main():
    print(f"{'Baseline':<14} {'pairs':>7} {'succ':>5} {'ASR':>7} {'TSR':>7} {'errs':>5} {'audit_ok':>9}")
    print("-" * 60)
    summary = {}
    for bl, files in MERGE_PLAN.items():
        out_jsonl, m = merge_baseline(bl, files)
        summary[bl] = m
        print(f"{bl:<14} "
              f"{m['n_attack_pairs']:>7} "
              f"{m['n_attack_succeeded']:>5} "
              f"{m['ASR']*100:>6.2f}% "
              f"{m['TSR']*100:>6.2f}% "
              f"{m['n_errors']:>5} "
              f"{(m.get('audit_chain_ok') or 0)*100:>8.0f}%")
    print()
    print("Saved merged files to:", DIR)
    return summary


if __name__ == "__main__":
    main()
