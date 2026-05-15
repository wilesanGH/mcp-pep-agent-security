# Phase 2 Result Summary — v8.5.5

Protocol: `experiments/jisa_v8_protocol.md` v8.5.5
Dataset: MVP-30 (20 attack T1–T4 + 10 benign N)
Frozen: 2026-05-06

## Completed experiments

| # | Experiment | Model | Baselines | Runs | Errors | Stats file |
|---|---|---|---|---|---|---|
| 1 | Main | deepseek-v4-pro | A, B-delim, B-data, B-enc, C, D0, D | 1050 | 0 | `stats/stats_2026-05-06_004255.json` |
| 2 | Cross-version | deepseek-chat | A, D0, D | 450 | 0 | `stats/stats_2026-05-05_050226.json` |
| 3 | Replication | qwen3.5-plus | A, B-delim, B-enc, C, D | 750 | 0 | `qwen_replication/stats/stats_2026-05-05_050227.json` |

Total valid runs: 2250/2250 (100%)
Chain validity: all ✅

## Main results: DeepSeek-v4-pro (Table 2 candidate)

| Baseline | ASR | TSR | FPR(call) | FPR(task) | FNR(call) |
|---|---|---|---|---|---|
| A (no_defense) | 40.0±0.0% | 82.0±4.5% | 0.0% | 0.0% | 100.0% |
| B-delim | 40.0±0.0% | 86.0±5.5% | 0.0% | 0.0% | 100.0% |
| B-data | 37.0±2.7% | 84.0±5.5% | 0.0% | 0.0% | 100.0% |
| B-enc | 35.0±0.0% | 80.0±0.0% | 0.0% | 0.0% | 100.0% |
| C (runtime, no IFC) | 9.0±2.2% | 76.0±5.5% | 5.8±1.9% | 34.0% | 43.0±7.1% |
| D0 (full, no path-norm) | 5.0±0.0% | 78.0±4.5% | 6.7±1.6% | 36.0% | 17.0±0.8% |
| D (full) | 5.0±0.0% | 82.0±4.5% | 4.6±0.3% | 30.0% | 16.6±1.5% |

IFC contribution (C→D): ASR −4.0pp, FNR(call) −25.6pp ✅

## Cross-version: deepseek-chat (Table 4 candidate)

| Baseline | ASR | TSR | FPR(call) | FNR(call) |
|---|---|---|---|---|
| A | 40.0±0.0% | 72.0±4.5% | 0.0% | 100% |
| D0 | 0.0±0.0% | 60.0±0.0% | 8.0±0.4% | 14.9±0.2% |
| D | 0.0±0.0% | 70.0±0.0% | 1.8±0.6% | 13.8±1.6% |

Path-norm story: D0→D FPR drops 8.0%→1.8%, stronger effect on older model.

## Replication: Qwen3.5-plus (Table 3 candidate)

| Baseline | ASR | TSR | FPR(call) | FNR(call) |
|---|---|---|---|---|
| A | 35.0±0.0% | 76.0±5.5% | 0.0% | 100% |
| B-delim | 36.0±2.2% | 94.0±8.9% | 0.0% | 100% |
| B-enc | 35.0±3.5% | 92.0±8.4% | 0.0% | 100% |
| C | 5.0±3.5% | 78.0±4.5% | 1.1±1.0% | 58.3±5.3% |
| D | 6.0±2.2% | 84.0±5.5% | 42.4±8.7% | 25.1±4.8% |

Known limitation: Qwen D FPR(call)=42.4% — IFC over-labels benign tool outputs as SENSITIVE.

## Attack attempt rates (model aggressiveness)

| Model | Baseline A | Baseline D |
|---|---|---|
| deepseek-v4-pro | 65.0% | 66.0% |
| deepseek-chat | ~65% | ~65% |
| qwen3.5-plus | ~60% | ~55% |

Models maintain attack attempts regardless of defense → PEP blocks at runtime, not via model dissuasion.

## File paths

```
results_jisa_v8/metrics/phase2_main_deepseek-v4-pro_mvp30_v8.5.3.json   (1050 records)
results_jisa_v8/metrics/phase2_cross_version_deepseek-chat_mvp30_v8.5.3.json (450 records)
results_jisa_v8/qwen_replication/metrics/phase2_replication_qwen3.5-plus_mvp30_v8.5.3.json (750 records)
results_jisa_v8/stats/stats_2026-05-06_004255.json  (main stats)
results_jisa_v8/stats/stats_2026-05-05_050226.json  (cross-version stats)
results_jisa_v8/qwen_replication/stats/stats_2026-05-05_050227.json  (qwen stats)
```

## Gate evaluation

| Gate | Status | Evidence |
|---|---|---|
| G1 path-norm | ✅ PASS | D FPR(task)=30% < D0 FPR(task)=36%; improvement direction correct |
| G2 5-repeat stability | ✅ PASS | Key metrics have tight CI (ASR std=0 for A/D) |
| G4 D-cons FPR | N/A | D-cons not tested in Phase 2 |
| G5 model-call failure | ✅ PASS | 0 provider_errors across all 2250 runs |
| G6 benign expansion | ⚠️ MONITOR | Qwen D FPR high; DeepSeek D FPR acceptable (4.6%) |
