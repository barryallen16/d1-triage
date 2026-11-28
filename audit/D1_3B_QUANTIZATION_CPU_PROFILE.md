# Quantization and single-pass scoring notes for Liquid AI d1-3B

Liquid AI's `d1-3B` (`LiquidAI/d1-3B-GGUF`) answers a binary decision in one prompt pass and reads probabilities from the final-position `yes`/`no` option logits without generating output tokens.
`d1-triage` uses the same prompt rendering for GPU scoring (`audit/d1_contrastive_lora_train.py`) and local GGUF inference (`scripts/test_q8_systemone.py`), which avoids multi-token JSON generation during offline scoring.

## How single-pass scoring works

1. `d1_triage/sink_finder.py` locates the matching sink statement in the Java method body and prefixes that line with `>>> [ALERT LINE n]:`.
2. The prompt wraps the rule name, CWE, file path, annotated Java window, the triage question, and the `true`/`false` criteria from `d1_triage/engine.py`.
3. `llama_cpp.Llama.eval()` processes the tokenized prompt in one forward pass, with no autoregressive decoding loop.
4. `scripts/test_q8_systemone.py` reads the terminal logits for `yes_forms` (`["yes", "Yes", "YES", " yes", " Yes"]`) and `no_forms` (`["no", "No", "NO", " no", " No"]`) and applies a two-class softmax to produce `P(TP)`.

Runtime depends on prompt token length, quantization format, and memory bandwidth rather than on generated answer length.

## Local GGUF runner (`Q8_0`)

`scripts/test_q8_systemone.py` scores `models/d1-3B-Q8_0.gguf` locally with `llama-cpp-python` (`n_ctx=2048`, `n_threads=4`, `logits_all=True`) against `DEMO_FINDINGS`.

`Q8_0` keeps logits close to FP16 on the one ranking task that matters here: pre-fix and post-fix methods that share a rule and differ by small `P(TP)` margins.
No automated quantization sweep (`Q4_K_M` vs `Q5_K_M` vs `Q8_0`) has been run on GHSA or Vul4J.
The FP16 results in `audit/TECHNICAL_REPORT.md` come from `audit/d1_lora_identity_ghsa.jsonl` and `audit/d1_lora_identity_vul4j.jsonl` on a T4 GPU.

## Observed benchmark measurements (FP16 on T4 GPU)

Timing and discrimination numbers below come from the committed prediction files and `audit/evaluate_d1.py`:

| Variant | L0 AUC | L2 AUC | L3 AUC | L3 Within-Rule AUC | L3 Swap Delta | Vul4J AUC (n=14) | Mean Loop Latency |
|---|---|---|---|---|---|---|---|
| Targeted Prompt | 0.6098 | 0.5843 | 0.6261 | 0.5761 | +0.0462 | N/A | 626.1 ms |
| Contrastive LoRA (v2) | 0.7119 | 0.7977 | 0.8339 | 0.6027 | +0.0724 | 0.5222 | 456.4 ms |

Mean loop latency averages the `seconds` field recorded per row across all 174 rows in `audit/d1_targeted_identity_ghsa.jsonl` and `audit/d1_lora_identity_ghsa.jsonl`, including tokenization and Python loop overhead.
With `P@90R = 0.3023` on L3 and `0.5222` on Vul4J (`n=14`), the FP16 LoRA checkpoint suits ranking alerts inside a queue; it does not support unattended CPU gating without further calibration and crypto/SSL training data.
