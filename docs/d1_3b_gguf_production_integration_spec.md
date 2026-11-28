# Local GGUF integration notes for d1-triage

`d1_triage/engine.py` currently ships `--mock` AST heuristic scoring for zero-dependency CLI and web demo runs.
`scripts/test_q8_systemone.py` demonstrates single-pass `Q8_0` GGUF scoring using `llama-cpp-python` on a local `models/d1-3B-Q8_0.gguf` file.
This note outlines how to wire that GGUF path directly into `D1TriageEngine` when `mock=False` is enabled in the future.

## Proposed architecture

Keep `d1_triage/engine.py` lightweight by default so `d1-triage --demo --mock` still installs with zero ML dependencies, and load `llama_cpp` lazily only when a `--gguf` path or downloaded local model is provided:

1. Download or point to a GGUF file (for example `models/d1-3B-Q8_0.gguf` via `scripts/download_q8_model.py`).
2. Render the exact prompt format used in training and `scripts/test_q8_systemone.py`: `build_annotated_prompt(...)` plus `TRIAGE_QUESTION` and `TRIAGE_CRITERIA`.
3. Call `llm.reset()` and `llm.eval(tokens)`, read terminal logits via `llm.eval_logits[-1]`, and compute softmax over `yes_forms` and `no_forms`.
4. Return `TriageResult` with `device="cpu"` (or `"metal"` / `"cuda"` when offloading layers) and actual measured `latency_ms`.

Two deployment modes make sense depending on caller lifecycle:

- In-process `llama-cpp-python`: best for single-shot CLI runs (`d1-triage --scan report.json`), with no background daemon or open port to manage.
- Local `llama-server` HTTP sidecar (`/v1/systemone`): best for persistent IDE plugins or editors where keeping weights warm in RAM avoids cold reload on each file save.

## Exporting a merged LoRA checkpoint to GGUF

The current LoRA training pipeline in `audit/d1_contrastive_lora_train.py` already merges the adapter into FP16 Hugging Face weights (`merged_model = peft_model.merge_and_unload()`).
Static merging avoids extra runtime adapter matrix math during CPU inference and leaves one model directory to convert with `llama.cpp`:

```bash
python convert_hf_to_gguf.py /path/to/d1_lora_contrastive_merged --outfile d1-3B-triage-f16.gguf --outtype f16
./build/bin/llama-quantize d1-3B-triage-f16.gguf d1-3B-triage-Q8_0.gguf Q8_0
```

Before swapping a quantized GGUF export into CLI defaults, verify its GHSA identity, GHSA swap control, and Vul4J scores against the FP16 baseline (`0.8339` L3 AUC, `0.6027` L3 within-rule AUC, `+0.0724` L3 swap delta) using `audit/evaluate_d1.py`.
