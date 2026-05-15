# Provenance Ledger

> Maps every quantitative claim in §4.2–§4.8 of the manuscript to its source result file in this reviewer pack, with SHA-256 checksums for integrity verification.

## How to use this ledger

1. Locate the manuscript claim by section number.
2. Read the corresponding source file from `reviewer-pack/`.
3. (Optional) Verify file integrity:
   ```bash
   shasum -a 256 -c <(grep -E '^[a-f0-9]{64} ' PROVENANCE.md)
   ```

## §4.2 — Controlled Evaluation (Scripted Mode)

| Claim (manuscript) | Source file | Notes |
|---|---|---|
| 90 scripted runs (3 baselines × 30 tasks) | `results/phase2_cross_version/phase2_cross_version_deepseek-chat_mvp30_v8.5.3.json` | Scripted-mode subset embedded |
| Table 3 metrics (A / D / D₀) | `results/stats/stats_summary.json` → `phase2_main` aggregate block | |

## §4.3 — IFC Ablation Study

| Claim | Source file |
|---|---|
| Δ_FNR = 26.4 pp (D vs D₀) | `results/phase2_main_deepseek-v4-pro/phase2_main_deepseek-v4-pro_mvp30_v8.5.3.json` → baselines `runtime_ablation`, `d0`, `full` |
| Aggregate ablation table | `results/stats/stats_summary.md` (Phase-2 block) |

## §4.4 — LLM-Driven Evaluation (deepseek-v4-pro MVP-30)

| Claim | Source file |
|---|---|
| 1050 runs (7 baselines × 30 tasks × 5 repeats) | `results/phase2_main_deepseek-v4-pro/phase2_main_deepseek-v4-pro_mvp30_v8.5.3.json` |
| Table 4: A=40.0% ASR, B-enc=35.0%, C=9.0%, D₀=5.0%, D=5.0% | same file → `aggregate_metrics` block |
| TSR D=82.0±4.5% | same |
| FPR(call) D=4.6±0.3%, FPR(task) D=30.0% | same |
| FNR(call) D=16.6%, D₀=43.0% | same |

### §4.4.1 — Qwen3.5-plus Replication and Cross-Version

| Claim | Source file |
|---|---|
| 150 Qwen3.5-plus runs (5 baselines × 30 tasks × 1 repeat) — security replication | `results/qwen_replication/metrics/phase2_replication_qwen3.5-plus_mvp30_v8.5.3.json` |
| Qwen ASR D=6.0%, TSR=84.0%, FPR(call)=42.4% | same; aggregate also in `results/stats/stats_summary.md` Phase-2 block |
| 90 deepseek-chat scripted runs — cross-version | `results/phase2_cross_version/phase2_cross_version_deepseek-chat_mvp30_v8.5.3.json` |
| deepseek-chat: D₀ FPR(call)=8.0±0.4%, D FPR(call)=1.8±0.6% | same |

## §4.5 — Enforcement Overhead

| Claim | Source file |
|---|---|
| Decision + audit ≈ 60 µs P50 per call (5,000 iterations) | `results/stats/stats_summary.json` → `latency` block (microbenchmark aggregates only — raw S1–S6 logs withheld) |
| Appendix B microbenchmark scenarios | aggregate latency reproducible from `stats_summary.json` |

## §4.6 — Audit Chain Integrity

| Claim | Verification |
|---|---|
| Hash chain verifies on all 1050 LLM Phase-2 runs, all 90 scripted runs, 118/120 LLM pilot runs | run `python3 verify_chain.py audit_log_samples/` (20-trace sample) and `python3 verify_chain.py results/cross_model/` (454 cross-model traces) |
| All sampled traces PASS | sample run produces "Summary: 20 PASS, 0 FAIL out of 20" and "Summary: 454 PASS, 0 FAIL out of 454" |
| Tail-truncation limitation (L4b) | reproducible by manually truncating any trace and re-running verify_chain — final event still verifies; only the absence is undetectable from forward chain alone |

## §4.7 — Cross-Model Observations (19-task subset)

| Claim | Source file |
|---|---|
| 456 runs (4 backends × 19 tasks × 2 baselines × 3 repeats) | `results/cross_model/{glm-4.7,kimi-k2.5,claude-haiku-4.5,llama-3.3-70b}/metrics/*.json` |
| GLM-4.7: A=42.9%, D=4.8% ASR | `results/cross_model/glm-4.7/metrics/eval_llm_glm-4_7_20260507_132533.json` |
| Kimi-K2.5: A=40.5%, D=0.0% ASR | `results/cross_model/kimi-k2.5/metrics/eval_llm_kimi-k2_5_20260507_140421.json` |
| Claude Haiku 4.5: A=28.6%, D=0.0% ASR | `results/cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_*.json` (5 batches concatenated; per-baseline aggregates in stats_summary.md) |
| LLaMA-3.3-70B: A=35.7%, D=16.7% ASR (residual T4) | `results/cross_model/llama-3.3-70b/metrics/eval_llm_meta-llama_llama-3_3-70b-instruct_*.json` |
| Coverage gap: LLaMA T4 D = identical to A (3/6) with zero DENY events | inspectable in `results/cross_model/llama-3.3-70b/audit_logs/` (each T4 trace shows policy_decision=ALLOW) |

## §4.8 — AgentDojo Workspace Pilot

| Claim | Source file |
|---|---|
| 780 runs (50 pairs × 5 repeats × 3 baselines) | `results/agentdojo/*_metrics.json` (smoke-validation snapshots; full 50-pair × 5-repeat aggregates summarised in `results/stats/stats_summary.md` AgentDojo block) |
| A: ASR_attempted=48.8%, ASR_valid=49.6%, valid-rate=98.5% | `results/stats/stats_summary.md` → AgentDojo block |
| B-enc: ASR=5.2%, TSR=85.8%, valid-rate=100% | same |
| D: ASR_attempted=18.4%, ASR_valid=22.7%, TSR=67.1%, valid-rate=81.9% (below 85% → directional only) | same |

## File checksums (SHA-256)

```
bc42371d36ba8a4b62539608e36093989ab2a73882b3cc5d837b03ead76d6df1  results/phase2_main_deepseek-v4-pro/phase2_main_deepseek-v4-pro_mvp30_v8.5.3.json
d8c3397a7501f94bcb734f22870e4b9ba9a387798af21e8631133292876255e4  results/phase2_cross_version/phase2_cross_version_deepseek-chat_mvp30_v8.5.3.json
790cc9808010621916193c2c64ada9e25ac6ed66200d064867b439a966c0329a  results/stats/stats_summary.json
a5d40eb6288994cf54b52ad43da08ff2dd5ebe90005f2875a7d7e18659d32199  results/stats/stats_summary.md
094ad99a671a4ce3e660bb0dace9a58bf6f24909262a2c4ae5e73dd57a6196e0  results/cross_model/glm-4.7/metrics/eval_llm_glm-4_7_20260507_132533.json
bf4d8f86051ab5a479383face2098da7ff6c2b709081bfb25907c2b11e4378bb  results/cross_model/kimi-k2.5/metrics/eval_llm_kimi-k2_5_20260507_140421.json
955bb83ea52c5ebac69ab8c75d0cb94ad82b98283ff354e39b722c60b5b1e1bb  results/cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_20260507_170414.json
26d1a73de7c85895198576e28e353110deeeabbab5d7da89ad4eb67254ff7475  results/cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_20260507_170427.json
b74d548aecec1a576f1d77efa4df78c2a3c61825bbf6b6f3824fe1f3c01b457c  results/cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_20260507_170545.json
1fa869ab42d2d8e630230c128388bc29c82e393693c2864622b24e7be023adf0  results/cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_20260507_170702.json
0245bd1a248098051aa53ea31e4a6f9cf5e93adeef242b9beef442c12fea5e43  results/cross_model/claude-haiku-4.5/metrics/eval_llm_anthropic_claude-haiku-4_5_20260507_173424.json
9072b22b27a461501db8ebf0f06012d2b47ed9161ce92b90bc1478f1b7c40369  results/cross_model/llama-3.3-70b/metrics/eval_llm_meta-llama_llama-3_3-70b-instruct_20260507_170421.json
9ada1e3c08abc3d1695fed1055e229c54a336084027d163846680392f3ff237a  results/cross_model/llama-3.3-70b/metrics/eval_llm_meta-llama_llama-3_3-70b-instruct_20260507_170432.json
de3a99811669434a89698e265dc04f373634593aaee2f8d8b7426dd5e698c430  results/cross_model/llama-3.3-70b/metrics/eval_llm_meta-llama_llama-3_3-70b-instruct_20260507_171710.json
a10efc7acbb42e275ec1f6f45402ad482d3f6f867f93e7d72fd5e0e140eb9410  results/qwen_replication/metrics/phase2_replication_qwen3.5-plus_mvp30_v8.5.3.json
d42873f4d8c860b95fb5f0c6f641d88c22f27bda9ddb0e1540a9178351385052  results/qwen_replication/stats/stats_2026-05-05_050227.json
da56364a16f3ebb37ebb948d7cdf9555a0cae13902caeccff7768286c2ca104f  results/agentdojo/banking_smoke_full_20260506_030812_metrics.json
4f584198ee5cfbbf91bbf819a3ecc4b38c66c50fc46615e02c50d8b6975ee5de  results/agentdojo/banking_smoke_full_20260506_031303_metrics.json
963ba46eacd242511adcfbfc7ea9bb980f1b24a2b50d493328a0e15f84258531  results/agentdojo/banking_smoke_no_defense_20260506_030643_metrics.json
e915b6df46a01e34b4e6aa5bce9901286eff0ed60b713a7f3e108d9a36ee9e83  results/agentdojo/banking_smoke_no_defense_20260506_030712_metrics.json
48e775e4f0972da6e199610e9eaeffe858111db4183acb664508c433343ec646  results/agentdojo/banking_smoke_no_defense_20260506_031226_metrics.json
```

To verify: write the lines above to a file `checksums.sha256`, then run

```bash
cd reviewer-pack/
shasum -a 256 -c checksums.sha256
```

All entries should report `OK`.
