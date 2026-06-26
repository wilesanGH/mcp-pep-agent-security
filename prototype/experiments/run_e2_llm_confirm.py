"""
experiments/run_e2_llm_confirm.py — LLM-mode confirmation for E1 + E2 (deepseek).

End-to-end confirmation under a REAL model that:
  (E2) the T3-reconstruction attacks manifest with a real model (the model
       paraphrases sensitive content into an outbound call) and that D-IT closes
       them end-to-end (D allows -> D-IT blocks).
  (E1) the expanded 30-task benign set's operational FPR(task) under the full
       system, with the usability token, when a real model produces the calls.

Backend: deepseek (the paper's primary model; cheapest). Uses run-level repeats.

Usage:
  python experiments/run_e2_llm_confirm.py --backend deepseek --repeats 3
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


def _load(directory: str) -> list[dict]:
    return [json.load(open(p, encoding="utf-8"))
            for p in sorted((_PROTO_ROOT / "datasets" / directory).glob("*.json"))]


def _interventions(path: str) -> dict:
    c = Counter(); rules = Counter()
    if not path or not Path(path).exists():
        return {"DENY": 0, "REQUIRE_CONFIRM": 0, "rules": {}}
    for line in open(path, encoding="utf-8"):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        dec = ev.get("policy_decision", "")
        rule = ev.get("matched_rule", "")
        if dec in ("DENY", "REQUIRE_CONFIRM"):
            c[dec] += 1
            if rule:
                rules[rule] += 1
    return {"DENY": c["DENY"], "REQUIRE_CONFIRM": c["REQUIRE_CONFIRM"], "rules": dict(rules)}


def run_security_llm(backend, model, repeats, results_dir):
    """T3R attacks under D vs D-IT, LLM mode."""
    tasks = _load("t3_reconstruction")
    out = {}
    for baseline in ("full", "d_it"):
        blocked = 0; total = 0; per = {}
        for task in tasks:
            tk = task["task_id"]; per[tk] = []
            for r in range(repeats):
                runner = AgentRunner.build(
                    baseline=baseline, backend=backend, model=model,
                    use_scripted=False, results_dir=results_dir, token_type="attack",
                )
                res = runner.run(task)
                total += 1
                if res.attack_blocked:
                    blocked += 1
                per[tk].append({
                    "blocked": res.attack_blocked,
                    "iv": _interventions(res.audit_log_path),
                    "error": res.error,
                })
        out[baseline] = {
            "n_runs": total, "n_blocked": blocked,
            "asr": round((total - blocked) / total, 4) if total else None,
            "per_task": per,
        }
    return out


def run_benign_llm(backend, model, repeats, results_dir):
    """30 benign under D, LLM mode, usability token. Operational FPR(task)."""
    tasks = _load("normal")
    baseline = "full"
    per = {}; fp_task_runs = 0; total = 0
    for task in tasks:
        tk = task["task_id"]; per[tk] = []
        for r in range(repeats):
            runner = AgentRunner.build(
                baseline=baseline, backend=backend, model=model,
                use_scripted=False, results_dir=results_dir, token_type="usability",
            )
            res = runner.run(task)
            iv = _interventions(res.audit_log_path)
            rule_keys = [k for k in iv["rules"] if k not in ("TOKEN", "TOKEN_LIMIT")]
            is_fp = len(rule_keys) > 0
            total += 1
            if is_fp:
                fp_task_runs += 1
            per[tk].append({"iv": iv, "rule_fp": is_fp, "error": res.error})
    return {
        "n_runs": total, "rule_fp_runs": fp_task_runs,
        "fpr_run_rule": round(fp_task_runs / total, 4) if total else None,
        "per_task": per,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="deepseek")
    ap.add_argument("--model", default=None)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--results-dir", default="results_v97_llm")
    ap.add_argument("--out", default="results/metrics/e2_llm_confirm.json")
    ap.add_argument("--skip-benign", action="store_true")
    ap.add_argument("--skip-security", action="store_true")
    args = ap.parse_args()

    print("=" * 64)
    print(f"E2/E1 LLM confirmation — backend={args.backend} repeats={args.repeats}")
    print("=" * 64)

    out = {"backend": args.backend, "model": args.model, "repeats": args.repeats}

    if not args.skip_security:
        print("\n[Security] T3-reconstruction D vs D-IT (LLM mode)...")
        sec = run_security_llm(args.backend, args.model, args.repeats, args.results_dir)
        out["security"] = sec
        for b in ("full", "d_it"):
            print(f"  {b:6}  ASR={sec[b]['asr']}  blocked={sec[b]['n_blocked']}/{sec[b]['n_runs']}")

    if not args.skip_benign:
        print("\n[Usability] 30 benign under D (LLM mode, usability token)...")
        ben = run_benign_llm(args.backend, args.model, args.repeats, args.results_dir)
        out["benign"] = ben
        print(f"  rule-FP runs={ben['rule_fp_runs']}/{ben['n_runs']}  "
              f"FPR(run,rule)={ben['fpr_run_rule']}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
