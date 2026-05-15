# Stats Summary — JISA v8.5.5 (generated 2026-05-08)

Auto-generated from frozen stats files. Do NOT edit manually.

## Phase 2 — MVP-30 (deepseek-v4-pro, 5 repeats)

| Baseline | ASR (mean±std) | TSR | FPR_call | FPR_task | FNR_call | n_valid |
|---|---|---|---|---|---|---|
| no_defense | 40.0% | 82.0±4.5% | 0.0% | 0.0% | 100.0% | 150 |
| prompt_delim | 40.0% | 86.0±5.5% | 0.0% | 0.0% | 100.0% | 150 |
| prompt_data | 37.0±2.7% | 84.0±5.5% | 0.0% | 0.0% | 100.0% | 150 |
| prompt_enc | 35.0% | 80.0% | 0.0% | 0.0% | 100.0% | 150 |
| runtime_ablation | 9.0±2.2% | 76.0±5.5% | 5.8% | 34.0% | 43.0% | 150 |
| d0 | 5.0% | 78.0±4.5% | 6.6% | 36.0% | 17.0% | 150 |
| full | 5.0% | 82.0±4.5% | 4.6% | 30.0% | 16.6% | 150 |

## Phase 2 — Cross-version (deepseek-chat) & Replication (Qwen3.5-plus)

| Experiment | Baseline | ASR | TSR | FPR_call | FNR_call |
|---|---|---|---|---|---|
| phase2_crossver | d0 | 0.0% | 60.0% | 8.0% | 14.9% |
| phase2_crossver | full | 0.0% | 70.0% | 1.8% | 13.8% |
| phase2_crossver | no_defense | 40.0% | 72.0% | 0.0% | 100.0% |
| phase2_qwen | full | 6.0% | 84.0% | 42.4% | 25.1% |
| phase2_qwen | no_defense | 35.0% | 76.0% | 0.0% | 100.0% |
| phase2_qwen | prompt_delim | 36.0% | 94.0% | 0.0% | 100.0% |
| phase2_qwen | prompt_enc | 35.0% | 92.0% | 0.0% | 100.0% |
| phase2_qwen | runtime_ablation | 5.0% | 78.0% | 1.1% | 58.3% |

## Phase 4 — Cross-model (19-task subset, 3 repeats, observational)

| Model | Baseline | ASR | FPR_task | FPR_call |
|---|---|---|---|---|
| GLM-4.7 | no_defense | 42.9% | 0.0% | 0.0% |
| GLM-4.7 | full | 4.8% | 60.0% | 42.5% |
| Kimi-K2.5 | no_defense | 40.5% | 0.0% | 0.0% |
| Kimi-K2.5 | full | 0.0% | 73.3% | 25.5% |
| Claude-Haiku | no_defense | 28.6% | 0.0% | 0.0% |
| Claude-Haiku | full | 0.0% | 20.0% | 3.8% |
| LLaMA-3.3-70B | no_defense | 35.7% | 0.0% | 0.0% |
| LLaMA-3.3-70B | full | 16.7% | 80.0% | 56.2% |

## Phase 3 — AgentDojo pilot (deepseek-v4-pro, 50 pairs × 5 repeats)

| Baseline | ASR(valid) | ASR(attempted) | TSR | FPR_call | valid_rate | Notes |
|---|---|---|---|---|---|---|
| A | 49.6% | 48.8% | 38.3% | 0.0% | 98.5% |  |
| B-enc | 5.2% | 5.2% | 85.8% | 0.0% | 100.0% |  |
| D | 22.7% | 18.4% | 67.1% | 0.0% | 81.9% | D valid_rate=81.9%, below 85% threshold; directional evidence only |
