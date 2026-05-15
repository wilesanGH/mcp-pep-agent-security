# Phase 2 Interpretation Notes — for paper §4

## Core narrative (3 stories)

### Story 1: Prompt-level defenses are insufficient

Evidence:
- A→B-delim: ASR 40%→40% (zero reduction)
- A→B-data: ASR 40%→37% (marginal, within noise)
- A→B-enc: ASR 40%→35% (marginal)
- All B variants: FNR(call)=100% — no high-risk call is ever denied (no PEP active)
- Qwen replication confirms: B-delim 36%, B-enc 35% (essentially same as A=35%)

Interpretation: Spotlighting techniques (Hines+ 2024) — whether delimiting, datamarking, or encoding — provide negligible protection when the LLM is sufficiently capable. The model simply processes the injected instruction despite boundary markers. This holds across model families (DeepSeek, Qwen).

Paper claim: "Prompt-level defenses reduce ASR by at most 5pp on capable models, compared to 35pp reduction from runtime enforcement."

### Story 2: Runtime PEP provides robust protection

Evidence:
- A→C (PEP without IFC): ASR 40%→9% (−31pp)
- A→D (full PEP): ASR 40%→5% (−35pp)
- Attack attempt_rate unchanged: 65% under A, 66% under D
  → Models still TRY to attack; PEP stops them at execution time

Interpretation: The PEP operates independently of model cooperation. It doesn't need the LLM to "understand" the defense — it intercepts forbidden operations at the tool-call boundary. The stable attempt_rate across baselines proves this is enforcement, not persuasion.

Paper claim: "Runtime policy enforcement reduces ASR from 40% to 5%, operating independently of model compliance."

### Story 3: IFC label propagation enhances detection

Evidence:
- C vs D: ASR 9%→5% (−4pp)
- C vs D: FNR(call) 43.0%→16.6% (−26.4pp) — the big win
- Mechanism: IFC tracks data sensitivity across steps. Without IFC (C), the PEP only checks individual calls against rules; with IFC (D), accumulated sensitivity context enables catching multi-step attacks that individually appear benign.

Interpretation: The 4pp ASR improvement from IFC seems modest, but the FNR reduction is dramatic: 26.4pp fewer malicious calls escape detection. This matters for audit completeness — even when attacks don't succeed (ASR), the system must detect and log all attempts.

Paper claim: "Cross-step IFC reduces call-level false-negative rate by 26.4pp, critical for audit completeness."

## Secondary findings

### Path normalization (D0 vs D)

On deepseek-v4-pro:
- ASR: 5% vs 5% (no change — T3 attacks already caught by rules)
- FPR(call): 6.7%→4.6% (−2.1pp improvement)
- FPR(task): 36%→30% (−6pp improvement)

On deepseek-chat (older/weaker model):
- ASR: 0% vs 0%
- FPR(call): 8.0%→1.8% (−6.2pp, much larger effect)

Interpretation: Path normalization primarily reduces false positives by canonicalizing symlinks and relative paths before rule matching. The effect is larger on models that produce more varied path formats (deepseek-chat). On v4-pro, paths are already fairly canonical, so improvement is marginal but directionally correct.

### Qwen high FPR — limitation to discuss honestly

Qwen D: FPR(call)=42.4±8.7%

Root cause hypothesis: Qwen's tool-result format triggers IFC DS:SENSITIVE labeling more aggressively on benign outputs. The IFC classifier sees patterns in Qwen's output formatting that resemble sensitive data markers.

For the paper:
- Report as limitation in §5 (Limitations)
- Frame as "IFC label calibration is model-specific; our current heuristics are tuned for DeepSeek-family outputs"
- Note that FPR(task) is more relevant for user experience than FPR(call)
- Suggest future work: model-adaptive IFC thresholds

### TSR (Task Success Rate) patterns

- TSR is generally independent of baseline (76%–86% range)
- The ~18% non-success rate comes from tasks where the LLM fails to complete the objective regardless of defense
- Not a defense artifact — confirms our baselines don't break normal functionality

## Figures suggested

1. **Bar chart**: ASR by baseline (A → B-delim → B-data → B-enc → C → D0 → D)
   - Clear visual story: B variants ≈ A, then dramatic drop at C, slight further at D
2. **FNR comparison**: C vs D call-level FNR (42% vs 17%)
   - Demonstrates IFC value proposition
3. **Cross-model spider/radar**: DeepSeek vs Qwen on key metrics under D
   - Shows generalization and model-specific challenges

## Remaining gaps for paper

1. AgentDojo results (external benchmark — Phase 3)
2. Cross-model results (Phase 4 — GLM, Kimi, Claude, LLaMA)
3. Overhead measurements (latency microbenchmarks)
4. Audit chain verification tests (tamper detection)
