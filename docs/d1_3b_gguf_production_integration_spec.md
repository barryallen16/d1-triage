# Local GGUF integration for d1-triage

`d1_triage/engine.py` ships `--mock` keyword heuristic scoring so the CLI and web demo run with no ML dependencies.
When `model_name` ends in `.gguf`, `D1TriageEngine` imports `llama_cpp` lazily and scores the prompt in a single pass, leaving the base install untouched.
`scripts/test_q8_systemone.py` is a standalone runner for the same path against a local `models/d1-3B-Q8_0.gguf` file.

## How the GGUF path runs

1. Download a GGUF file, for example `models/d1-3B-Q8_0.gguf` via `scripts/download_q8_model.py`.
2. Render the training prompt with `build_annotated_prompt(...)` plus `TRIAGE_QUESTION` and `TRIAGE_CRITERIA`.
3. Call `llm.reset()` and `llm.eval(tokens)`, read the terminal logits from `llm.eval_logits[-1]`, and take a softmax over the `yes` and `no` token forms.
4. Return a `TriageResult` with `device="cpu"` (or `"metal"` / `"cuda"` when offloading layers) and the measured `latency_ms`.

Two deployment modes fit different caller lifecycles:

- In-process `llama-cpp-python` for single-shot CLI runs (`d1-triage --scan report.json`), with no daemon or open port.
- A local `llama-server` HTTP sidecar for editors and IDE plugins that keep weights warm between file saves.

## Exporting a merged LoRA checkpoint to GGUF

`audit/d1_contrastive_lora_train.py` merges the adapter into FP16 Hugging Face weights (`merged_model = peft_model.merge_and_unload()`).
Static merging avoids adapter matrix math at inference time and leaves one directory to convert:

```bash
python convert_hf_to_gguf.py /path/to/d1_lora_contrastive_merged --outfile d1-3B-triage-f16.gguf --outtype f16
./build/bin/llama-quantize d1-3B-triage-f16.gguf d1-3B-triage-Q8_0.gguf Q8_0
```

Before changing CLI defaults to a quantized export, check its GHSA identity, GHSA swap control, and Vul4J scores against the FP16 baseline (`0.8339` L3 AUC, `0.6027` L3 within-rule AUC, `+0.0724` L3 swap delta) with `audit/evaluate_d1.py`.
