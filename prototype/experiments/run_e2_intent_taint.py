"""
experiments/run_e2_intent_taint.py — E2: Intent-taint conservative-DS evaluation.

R1/R2/R3 major-revision experiment E2. Quantifies the security/usability
trade-off of the intent-taint conservative-DS policy (baseline D-IT) versus the
standard full system (baseline D), in SCRIPTED mode (deterministic, no LLM cost).

Two measurements:
  1. Security gain  — T3-reconstruction attacks (datasets/t3_reconstruction/):
       denied out-of-scope read -> paraphrased (regex-evading) exfiltration.
       Reports attack-blocked rate under D vs D-IT.
  2. Usability cost — benign tasks (datasets/normal/) run on the usability token
       (permits send_email + shell so benign outbound reaches R01/R02/R05).
       Reports per-task intervention counts (DENY + REQUIRE_CONFIRM, separated)
       under D vs D-IT, so any added friction from the conservative policy is
       visible.

Usage:
  python experiments/run_e2_intent_taint.py
  python experiments/run_e2_intent_taint.py --out results/metrics/e2_intent_taint.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

_PROTO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROTO_ROOT))

from agent_runner import AgentRunner  # noqa: E402
from audit.logger import AuditLogger  # noqa: E402


def _load_tasks(directory: Path) -> list[dict]:
    out = []
    for p in sorted(directory.glob("*.json")):
        with open(p, encoding="utf-8") as f:
            out.append(json.load(f))
    return out


def _count_interventions(audit_log_path: str) -> dict:
    """Read a trace audit log; count DENY and REQUIRE_CONFIRM separately."""
    counts = Counter()
    rules = Counter()
    if not audit_log_path or not Path(audit_log_path).exists():
        return {"DENY": 0, "REQUIRE_CONFIRM": 0, "rules": {}}
    with open(audit_log_path, encoding="utf-8") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            dec = ev.get("policy_decision", "")
            rule = ev.get("matched_rule", "")
            if dec in ("DENY", "REQUIRE_CONFIRM"):
                counts[dec] += 1
                if rule:
                    rules[rule] += 1
    return {"DENY": counts["DENY"], "REQUIRE_CONFIRM": counts["REQUIRE_CONFIRM"],
            "rules": dict(rules)}


def run_security(baselines: list[str], results_dir: str) -> dict:
    """T3-reconstruction attacks: attack-blocked rate per baseline."""
    tasks = _load_tasks(_PROTO_ROOT / "datasets" / "t3_reconstruction")
    out = {}
    for baseline in baselines:
        # Attack token: includes send_email so the PEP (not least-privilege) is
        # the sole defense, matching the security-claim configuration.
        runner = AgentRunner.build(
            baseline=baseline, use_scripted=True,
            results_dir=results_dir, token_type="attack",
        )
        per_task = {}
        blocked = 0
        for task in tasks:
            res = runner.run(task)
            per_task[task["task_id"]] = {
                "attack_blocked": res.attack_blocked,
                "interventions": _count_interventions(res.audit_log_path),
            }
            if res.attack_blocked:
                blocked += 1
        n = len(tasks)
        out[baseline] = {
            "n_attacks": n,
            "n_blocked": blocked,
            "block_rate": round(blocked / n, 4) if n else None,
            "asr": round((n - blocked) / n, 4) if n else None,
            "per_task": per_task,
        }
    return out


def run_usability(baselines: list[str], results_dir: str,
                  subdir: str = "normal") -> dict:
    """Benign tasks on the usability token: intervention counts per baseline."""
    tasks = _load_tasks(_PROTO_ROOT / "datasets" / subdir)
    out = {}
    for baseline in baselines:
        runner = AgentRunner.build(
            baseline=baseline, use_scripted=True,
            results_dir=results_dir, token_type="usability",
        )
        per_task = {}
        total_deny = 0
        total_confirm = 0
        tasks_with_intervention = 0
        for task in tasks:
            res = runner.run(task)
            iv = _count_interventions(res.audit_log_path)
            per_task[task["task_id"]] = iv
            total_deny += iv["DENY"]
            total_confirm += iv["REQUIRE_CONFIRM"]
            if iv["DENY"] + iv["REQUIRE_CONFIRM"] > 0:
                tasks_with_intervention += 1
        n = len(tasks)
        out[baseline] = {
            "n_benign": n,
            "total_DENY": total_deny,
            "total_REQUIRE_CONFIRM": total_confirm,
            "total_interventions": total_deny + total_confirm,
            "tasks_with_any_intervention": tasks_with_intervention,
            "fpr_task_any": round(tasks_with_intervention / n, 4) if n else None,
            "interventions_per_task": round((total_deny + total_confirm) / n, 4) if n else None,
            "per_task": per_task,
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baselines", nargs="+", default=["full", "d_it"])
    ap.add_argument("--out", default="results/metrics/e2_intent_taint.json")
    ap.add_argument("--results-dir", default="results")
    args = ap.parse_args()

    print("=" * 64)
    print("E2 — Intent-Taint Conservative-DS Evaluation (scripted mode)")
    print(f"Baselines: {args.baselines}")
    print("=" * 64)

    security = run_security(args.baselines, args.results_dir)
    usability = run_usability(args.baselines, args.results_dir, subdir="normal")
    controls = run_usability(args.baselines, args.results_dir, subdir="benign_controls")

    print("\n--- SECURITY (T3-reconstruction attacks) ---")
    print(f"{'baseline':<10} {'n':>4} {'blocked':>8} {'block_rate':>11} {'ASR':>7}")
    for b in args.baselines:
        s = security[b]
        print(f"{b:<10} {s['n_attacks']:>4} {s['n_blocked']:>8} "
              f"{s['block_rate']:>11} {s['asr']:>7}")

    def _print_usability(title, table):
        print(f"\n--- {title} ---")
        print(f"{'baseline':<10} {'n':>4} {'DENY':>6} {'CONFIRM':>8} "
              f"{'tasks_iv':>9} {'fpr_any':>8} {'iv/task':>8}")
        for b in args.baselines:
            u = table[b]
            print(f"{b:<10} {u['n_benign']:>4} {u['total_DENY']:>6} "
                  f"{u['total_REQUIRE_CONFIRM']:>8} "
                  f"{u['tasks_with_any_intervention']:>9} "
                  f"{u['fpr_task_any']:>8} {u['interventions_per_task']:>8}")

    _print_usability("USABILITY — standard benign tasks (datasets/normal)", usability)
    _print_usability("USABILITY — intent-taint controls (denied read + benign outbound)", controls)

    out_path = Path(args.results_dir) / "metrics" / "e2_intent_taint.json" \
        if args.out == "results/metrics/e2_intent_taint.json" else Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"security": security, "usability_standard": usability,
                   "usability_controls": controls}, f,
                  indent=2, ensure_ascii=False)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
