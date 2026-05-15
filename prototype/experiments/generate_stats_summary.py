"""
generate_stats_summary.py  — Phase 5 claim ledger generator

Reads the three frozen Phase-2 stats files, plus Phase-4 cross-model metrics,
and produces:
  results_jisa_v8/stats_summary.json   — machine-readable claim ledger
  results_jisa_v8/stats_summary.md     — human-readable table

Every entry records:
  experiment, model, baseline, metric, mean, std, n,
  source_file (path), source_sha256, section_in_paper, table_in_paper
"""

from __future__ import annotations
import hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

PROTO_ROOT = Path(__file__).parent.parent
RESULTS    = PROTO_ROOT / "results_jisa_v8"

# ---------------------------------------------------------------------------
# Source files (frozen)
# ---------------------------------------------------------------------------
FROZEN = {
    "phase2_main": RESULTS / "stats/stats_2026-05-06_004255.json",
    "phase2_crossver": RESULTS / "stats/stats_2026-05-05_050226.json",
    "phase2_qwen": RESULTS / "qwen_replication/stats/stats_2026-05-05_050227.json",
}

PHASE4_METRICS = {
    "GLM-4.7":       RESULTS / "phase4_cross_model/glm-4.7/metrics/eval_llm_glm-4_7_20260507_132533.json",
    "Kimi-K2.5":     RESULTS / "phase4_cross_model/kimi-k2.5/metrics/eval_llm_kimi-k2_5_20260507_140421.json",
    "Claude-Haiku":  RESULTS / "phase4_cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_20260507_173424.json",
    "LLaMA-3.3-70B": RESULTS / "phase4_cross_model/llama-3.3-70b/metrics/eval_llm_meta-llama_llama-3_3-70b-instruct_20260507_171710.json",
}

AGENTDOJO_METRICS = {
    "A":     RESULTS / "agentdojo/workspace_deepseek/pilot_workspace_no_defense_r5_20260507_130802_metrics.json",
    "B-enc": RESULTS / "agentdojo/workspace_deepseek/pilot_workspace_prompt_enc_r5_20260507_145841_metrics.json",
    "D":     RESULTS / "agentdojo/workspace_deepseek/pilot_workspace_full_r5_20260507_173009_metrics.json",
}

METRIC_KEYS = ["ASR", "TSR", "FPR_call", "FPR_task", "FNR_call", "attack_attempt_rate"]

# Paper section/table mapping
PAPER_MAP = {
    ("phase2_main",    "no_defense"):        ("§4.4", "Table 6"),
    ("phase2_main",    "prompt_delim"):      ("§4.4", "Table 6"),
    ("phase2_main",    "prompt_data"):       ("§4.4", "Table 6"),
    ("phase2_main",    "prompt_enc"):        ("§4.4", "Table 6"),
    ("phase2_main",    "runtime_ablation"):  ("§4.3/§4.4", "Table 5/6"),
    ("phase2_main",    "d0"):                ("§4.4", "Table 6"),
    ("phase2_main",    "full"):              ("§4.4", "Table 6"),
    ("phase2_crossver","no_defense"):        ("§4.4", "Table 7"),
    ("phase2_crossver","d0"):                ("§4.4", "Table 7"),
    ("phase2_crossver","full"):              ("§4.4", "Table 7"),
    ("phase2_qwen",    "no_defense"):        ("§4.4", "Table 8 candidate"),
    ("phase2_qwen",    "runtime_ablation"):  ("§4.4", "Table 8 candidate"),
    ("phase2_qwen",    "full"):              ("§4.4", "Table 8 candidate"),
}

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()

def fmt(v, digits=1):
    if v is None: return "N/A"
    return f"{v*100:.{digits}f}%"

def fmt_std(mean, std, digits=1):
    if mean is None: return "N/A"
    if std is None or std == 0:
        return f"{mean*100:.{digits}f}%"
    return f"{mean*100:.{digits}f}±{std*100:.{digits}f}%"

# ---------------------------------------------------------------------------
# Harvest Phase-2 stats
# ---------------------------------------------------------------------------
entries = []

for exp_id, path in FROZEN.items():
    file_hash = sha256_file(path)
    d = json.load(open(path))
    meta = d.get("meta", {})
    model = meta.get("first_source_meta", {}).get("model", exp_id)

    for bl_name, bl_data in d.get("per_baseline", {}).items():
        metrics = bl_data.get("metrics", {})
        sec, tbl = PAPER_MAP.get((exp_id, bl_name), ("pending", "pending"))
        entry = {
            "experiment": exp_id,
            "model": model,
            "baseline": bl_name,
            "n_runs_total": bl_data.get("n_runs_total"),
            "n_runs_valid": bl_data.get("n_runs_valid"),
            "n_repeats": bl_data.get("n_repeats"),
            "source_file": str(path.relative_to(PROTO_ROOT)),
            "source_sha256": file_hash,
            "section": sec,
            "table": tbl,
            "metrics": {},
        }
        for mk in METRIC_KEYS:
            if mk in metrics:
                mv = metrics[mk]
                entry["metrics"][mk] = {
                    "mean": mv.get("mean"),
                    "std":  mv.get("std"),
                    "n":    mv.get("n"),
                }
        entries.append(entry)

# ---------------------------------------------------------------------------
# Harvest Phase-4 cross-model
# ---------------------------------------------------------------------------
for model_name, path in PHASE4_METRICS.items():
    if not path.exists():
        print(f"  WARNING: {path} not found, skipping", file=sys.stderr)
        continue
    file_hash = sha256_file(path)
    d = json.load(open(path))
    raw = d.get("metrics", {})
    for bl in ["no_defense", "full"]:
        if bl not in raw: continue
        v = raw[bl]
        entry = {
            "experiment": "phase4_crossmodel",
            "model": model_name,
            "baseline": bl,
            "n_runs_total": v.get("n_attacks", 0) + v.get("n_normals", 0),
            "n_runs_valid": None,
            "n_repeats": 3,
            "source_file": str(path.relative_to(PROTO_ROOT)),
            "source_sha256": file_hash,
            "section": "§4.7",
            "table": "Table 9",
            "metrics": {
                "ASR":            {"mean": v.get("ASR"),      "std": None, "n": v.get("n_attacks")},
                "TSR":            {"mean": v.get("TSR"),      "std": None, "n": v.get("n_attacks")},
                "FPR_call":       {"mean": v.get("FPR_call"), "std": None, "n": v.get("n_normals")},
                "FPR_task":       {"mean": v.get("FPR_task"), "std": None, "n": v.get("n_normals")},
                "FNR_call":       {"mean": v.get("FNR_call"), "std": None, "n": v.get("n_attacks")},
                "attempt_rate":   {"mean": v.get("llm_attempt_rate"), "std": None, "n": None},
            },
        }
        entries.append(entry)

# ---------------------------------------------------------------------------
# Harvest Phase-3 AgentDojo
# ---------------------------------------------------------------------------
for bl_name, path in AGENTDOJO_METRICS.items():
    if not path.exists():
        print(f"  WARNING: {path} not found", file=sys.stderr)
        continue
    file_hash = sha256_file(path)
    d = json.load(open(path))
    m = d.get("metrics", {})
    entry = {
        "experiment": "phase3_agentdojo",
        "model": "deepseek-v4-pro",
        "baseline": bl_name,
        "n_runs_total": m.get("n_attack_pairs", 0) + m.get("n_benign_pairs", 0),
        "n_runs_valid": m.get("n_attack_pairs_valid"),
        "n_repeats": 5,
        "source_file": str(path.relative_to(PROTO_ROOT)),
        "source_sha256": file_hash,
        "section": "§4.8",
        "table": "Table 10",
        "notes": f"D valid_rate={m.get('valid_run_rate',0)*100:.1f}%, below 85% threshold; directional evidence only" if bl_name == "D" else "",
        "metrics": {
            "ASR_valid":     {"mean": m.get("ASR"),           "std": None, "n": m.get("n_attack_pairs_valid")},
            "ASR_attempted": {"mean": m.get("ASR_attempted"),  "std": None, "n": m.get("n_attack_pairs")},
            "TSR":           {"mean": m.get("TSR"),            "std": None, "n": m.get("n_attack_pairs_valid")},
            "FPR_call":      {"mean": m.get("FPR_call"),       "std": None, "n": m.get("n_benign_pairs")},
            "valid_rate":    {"mean": m.get("valid_run_rate"), "std": None, "n": m.get("n_attack_pairs")},
        },
    }
    entries.append(entry)

# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------
out_json = RESULTS / "stats_summary.json"
# Build all-source hash map (all unique source files referenced by any entry)
all_source_paths = set()
for e in entries:
    sp = PROTO_ROOT / e["source_file"]
    if sp.exists():
        all_source_paths.add(sp)

# IFC contribution note: paper reports 26.4pp derived from DISPLAYED rounded values
# (43.0% - 16.6% = 26.4pp). Raw diff: 43.03% - 16.58% = 26.45pp → 26.4pp at 1 decimal.
# Convention: difference of one-decimal rounded displayed percentages, not raw float diff.
ifc_contribution_note = (
    "IFC C→D FNR_call reduction: 43.0% - 16.6% = 26.4pp "
    "(displayed-value arithmetic; raw diff = 26.45pp rounds to 26.4pp at 1 decimal)"
)

summary = {
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "generator": "experiments/generate_stats_summary.py",
    "n_entries": len(entries),
    "ifc_contribution_note": ifc_contribution_note,
    "all_source_hashes": {
        str(p.relative_to(PROTO_ROOT)): sha256_file(p)
        for p in sorted(all_source_paths)
    },
    "frozen_phase2_source_hashes": {
        exp_id: sha256_file(p) for exp_id, p in FROZEN.items() if p.exists()
    },
    "entries": entries,
}
out_json.write_text(json.dumps(summary, indent=2))
print(f"Written: {out_json} ({len(entries)} entries)")

# ---------------------------------------------------------------------------
# Write human-readable Markdown table
# ---------------------------------------------------------------------------
out_md = RESULTS / "stats_summary.md"
lines = [
    "# Stats Summary — JISA v8.5.5 (generated " + datetime.now().strftime('%Y-%m-%d') + ")",
    "",
    "Auto-generated from frozen stats files. Do NOT edit manually.",
    "",
    "## Phase 2 — MVP-30 (deepseek-v4-pro, 5 repeats)",
    "",
    "| Baseline | ASR (mean±std) | TSR | FPR_call | FPR_task | FNR_call | n_valid |",
    "|---|---|---|---|---|---|---|",
]
p2_bl_order = ["no_defense", "prompt_delim", "prompt_data", "prompt_enc", "runtime_ablation", "d0", "full"]
p2_entries = {e["baseline"]: e for e in entries if e["experiment"] == "phase2_main"}
for bl in p2_bl_order:
    if bl not in p2_entries: continue
    e = p2_entries[bl]
    m = e["metrics"]
    def g(k): return m.get(k, {})
    lines.append(f"| {bl} | {fmt_std(g('ASR').get('mean'), g('ASR').get('std'))} | {fmt_std(g('TSR').get('mean'), g('TSR').get('std'))} | {fmt(g('FPR_call').get('mean'))} | {fmt(g('FPR_task').get('mean'))} | {fmt(g('FNR_call').get('mean'))} | {e['n_runs_valid']} |")

lines += [
    "",
    "## Phase 2 — Cross-version (deepseek-chat) & Replication (Qwen3.5-plus)",
    "",
    "| Experiment | Baseline | ASR | TSR | FPR_call | FNR_call |",
    "|---|---|---|---|---|---|",
]
for exp in ["phase2_crossver", "phase2_qwen"]:
    for e in entries:
        if e["experiment"] != exp: continue
        m = e["metrics"]
        def g(k): return m.get(k, {})
        lines.append(f"| {exp} | {e['baseline']} | {fmt(g('ASR').get('mean'))} | {fmt(g('TSR').get('mean'))} | {fmt(g('FPR_call').get('mean'))} | {fmt(g('FNR_call').get('mean'))} |")

lines += [
    "",
    "## Phase 4 — Cross-model (19-task subset, 3 repeats, observational)",
    "",
    "| Model | Baseline | ASR | FPR_task | FPR_call |",
    "|---|---|---|---|---|",
]
for e in entries:
    if e["experiment"] != "phase4_crossmodel": continue
    m = e["metrics"]
    def g(k): return m.get(k, {})
    lines.append(f"| {e['model']} | {e['baseline']} | {fmt(g('ASR').get('mean'))} | {fmt(g('FPR_task').get('mean'))} | {fmt(g('FPR_call').get('mean'))} |")

lines += [
    "",
    "## Phase 3 — AgentDojo pilot (deepseek-v4-pro, 50 pairs × 5 repeats)",
    "",
    "| Baseline | ASR(valid) | ASR(attempted) | TSR | FPR_call | valid_rate | Notes |",
    "|---|---|---|---|---|---|---|",
]
for e in entries:
    if e["experiment"] != "phase3_agentdojo": continue
    m = e["metrics"]
    def g(k): return m.get(k, {})
    vr = g('valid_rate').get('mean')
    vr_str = f"{vr*100:.1f}%" if vr else "N/A"
    notes = e.get("notes", "")
    lines.append(f"| {e['baseline']} | {fmt(g('ASR_valid').get('mean'))} | {fmt(g('ASR_attempted').get('mean'))} | {fmt(g('TSR').get('mean'))} | {fmt(g('FPR_call').get('mean'))} | {vr_str} | {notes} |")

out_md.write_text("\n".join(lines) + "\n")
print(f"Written: {out_md}")
