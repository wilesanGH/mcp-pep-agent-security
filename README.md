# MCP-PEP — Runtime Policy Enforcement and Observable Auditing for MCP-Based LLM Agents

Replication package for the manuscript *"Beyond Prompt-Level Defense: Runtime Policy Enforcement and Observable Auditing for MCP-Based LLM Agents"*.

> **Status (2026-05-15)**: Manuscript under preparation for submission. Repository tracks the experimental code, dataset, frozen result files, and provenance ledger that underpin the quantitative claims of §4 in the paper.

## What's here

```
mcp-pep-agent-security/
├── prototype/              # PEP reference implementation
│   ├── pep/                #   enforcer, rules, label tracker, capability token, DS detector, path normaliser
│   ├── audit/              #   SHA-256 hash-chained audit logger + replay verifier
│   ├── configs/            #   CapabilityToken and per-baseline configurations
│   ├── experiments/        #   evaluation runners (scripted + LLM-driven)
│   ├── tests/              #   unit tests
│   ├── tools/              #   helper utilities (path normaliser, fingerprint, etc.)
│   ├── agent_runner.py     #   single-trace agent runner
│   ├── llm_client.py       #   OpenAI-compatible LLM client adapter
│   └── requirements.txt
├── data/
│   ├── MVP-30-attacks/     # 20 adversarial tasks (T1 path/deletion ×4, T2 multi-hop ×8, T3 user-guided ×4, T4 high-freq ×4)
│   └── MVP-30-normal/      # 10 benign tasks
├── results/                # Frozen experimental data
│   ├── metrics/            #   Phase-2 main + cross-version JSON metric files (1050 + 90 runs, deepseek-v4-pro + deepseek-chat)
│   ├── phase4_cross_model/ #   Cross-model observation: 456 runs across GLM-4.7, Kimi-K2.5, Claude Haiku 4.5, LLaMA-3.3-70B
│   ├── qwen_replication/   #   §4.4.1 Qwen3.5-plus security-effect replication (150 runs)
│   ├── agentdojo/          #   AgentDojo workspace pilot snapshots
│   ├── audit_logs/         #   1596 per-trace SHA-256 hash-chained audit logs from Phase-2
│   ├── stats/              #   Aggregate statistics per phase
│   ├── stats_summary.json
│   └── stats_summary.md    #   Human-readable table of all headline numbers
├── tools/
│   └── verify_chain.py     # Standalone audit-chain verifier (Python stdlib only)
├── PROVENANCE.md           # Per-claim mapping: every §4.2–§4.8 number → source file (with SHA-256)
├── LICENSE                 # MIT
└── README.md
```

## Quickstart — verify the audit chain claim (§4.6)

```bash
# No installation needed; pure stdlib.
python3 tools/verify_chain.py results/audit_logs/
# Expected: "Summary: <N> PASS, 0 FAIL out of <N> files"

python3 tools/verify_chain.py results/phase4_cross_model/
# Expected: "Summary: 454 PASS, 0 FAIL out of 454 files"
```

The verifier mirrors the hash convention of `prototype/audit/logger.py`:

```
event_hash = sha256(json.dumps({all fields except event_hash},
                                sort_keys=True, ensure_ascii=False))
```

The script also detects every standard tampering mode: value modification, hash forgery, interior event deletion, and event reordering. The known unprotected mode (tail truncation) is documented in §4.6 (L4b) of the paper.

## Quickstart — run the PEP prototype

```bash
cd prototype/
pip install -r requirements.txt

# Scripted (no LLM) mode — fast, deterministic
python3 experiments/run_scripted.py --baseline full --dataset ../data/MVP-30-attacks

# LLM-driven mode — needs an OpenAI-compatible API endpoint
export LLM_API_KEY=sk-...
export LLM_BASE_URL=https://api.deepseek.com/v1
python3 experiments/run_llm.py --baseline full --model deepseek-v4-pro
```

See `prototype/experiments/README.md` and `prototype/configs/` for baseline definitions.

## Verifying paper claims

See [PROVENANCE.md](PROVENANCE.md) for the per-claim mapping from manuscript §4.2–§4.8 to source result files, with SHA-256 checksums.

Headline aggregates are reproduced in `results/stats/stats_summary.md`:

| Phase | Backend | Baseline | ASR | TSR | Source |
|---|---|---|---|---|---|
| Phase 2 main | deepseek-v4-pro | A (no defence) | 40.0% | 82.0% | `results/metrics/phase2_main_deepseek-v4-pro_mvp30_v8.5.3.json` |
| Phase 2 main | deepseek-v4-pro | B-enc (Spotlighting) | 35.0% | 80.0% | same |
| Phase 2 main | deepseek-v4-pro | D (full PEP) | 5.0% | 82.0% | same |
| Phase 2 replication | Qwen3.5-plus | D | 6.0% | 84.0% | `results/qwen_replication/metrics/phase2_replication_qwen3.5-plus_mvp30_v8.5.3.json` |
| Phase 4 cross-model | GLM-4.7 | D | 4.8% | — | `results/phase4_cross_model/glm-4.7/metrics/` |
| Phase 4 cross-model | Kimi-K2.5 | D | 0.0% | — | `results/phase4_cross_model/kimi-k2.5/metrics/` |
| Phase 4 cross-model | Claude Haiku 4.5 | D | 0.0% | — | `results/phase4_cross_model/claude-haiku-4.5/metrics/` |
| Phase 4 cross-model | LLaMA-3.3-70B | D | 16.7% | — | `results/phase4_cross_model/llama-3.3-70b/metrics/` |

## Citation

Manuscript under preparation. A preprint and citation block will be added here when available. Until then, please cite this repository directly:

```bibtex
@software{wang2026mcppep,
  author       = {Wang, Shanshan and Xue, Ye and Wang, Dan and Li, Rende},
  title        = {{MCP-PEP}: Runtime Policy Enforcement and Observable Auditing for MCP-Based LLM Agents},
  year         = {2026},
  url          = {https://github.com/<username>/mcp-pep-agent-security},
  note         = {Replication package for the manuscript "Beyond Prompt-Level Defense"},
}
```

## License

MIT License — see `LICENSE`. Reuse encouraged for research, teaching, and security tooling.

