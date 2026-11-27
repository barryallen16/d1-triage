# Static Analysis Alert Triage with Liquid AI d1-3B

Static analysis scanners like Semgrep flag unsafe Java patterns with high recall, but false-positive rates often exceed 70%.
Automating alert triage with language models can save manual review time, but standard benchmarks evaluate against coarse file- or method-level proxies instead of verified security fix hunks.

I evaluated Liquid AI's hybrid `d1-3B` model on real-world Java static analysis alerts from 68 CVE-associated GitHub advisories (174 rows) and 126 Vul4J repositories (14 rows).
The audit uncovered two failure modes: shortcut learning from unaligned line numbers, and distribution mismatch during contrastive fine-tuning.

## 1. Label levels and audit findings

Standard benchmarks label an alert as a True Positive if it falls anywhere inside a file or method touched by a security commit (Level 0, location proxy).
That introduces label noise because security commits also touch build files, tests, and unrelated helpers.

I split the 174 GHSA findings into four stricter label levels:

- L0 (Location proxy): Finding is in any method touched by the vulnerability commit (85 TP of 174 rows).
- L1 (Hunk only): Finding line sits inside a modified fix hunk (44 TP of 174 rows).
- L2 (Stored plus CWE): Finding rule CWE matches the advisory CVE CWE (53 TP of 174 rows).
- L3 (Hunk plus CWE): Finding line is inside the fix hunk and matches the CVE CWE (28 TP of 174 rows).

Zero-shot `d1-3B` scored `0.8372` L3 AUC, `0.4297` L0 within-rule AUC, and `+0.0202` swap-window delta.
Two facts explain that gap:
First, rule base rates in the dataset are heavily skewed (`documentbuilderfactory-disallow-doctype-decl-missing` is 91% L0 TP while `formatted-sql-string` is 4% L0 TP), so predicting from rule names alone yields high overall AUC.
Second, Semgrep reports 1-based file line numbers while the snippet extractor passed unnumbered method bodies, so the model could not tell which statement triggered the alert.

## 2. Statement-level sink grounding

To anchor the model on the flagged statement, [sink_finder.py](../d1_triage/sink_finder.py) matches the rule's sink pattern and tags that line in the prompt:

```java
>>> [ALERT LINE 317]: transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

Under paired rule-swap controls (shuffling code windows within the same rule family):

- L0 within-rule AUC rises from `0.4297` to `0.5986`, and the bootstrap share below random chance drops from `70.7%` to `8.9%`.
- L2 within-rule AUC rises from `0.4571` to `0.6321`.
- Swap delta stays positive across all four levels (`+0.0749` on L0, `+0.0468` on L1, `+0.0780` on L2, `+0.0462` on L3), showing the model reads the tagged Java code.
- Overall L3 AUC drops from `0.8372` to `0.6261` because the model no longer relies as heavily on rule-name priors.

## 3. Contrastive fine-tuning and its failure mode

Fine-tuning on synthetic Juliet cases hurt real-world transfer (`0.449` within-rule AUC) because Juliet uses artificial `bad()` and `good()` names.
To avoid leakage, I extracted 40 held-out advisory patches with zero overlap against the 68 evaluation advisories, producing 208 pre-fix (TP) and 208 post-fix (FP) pairs in [contrastive_train.jsonl](contrastive_train.jsonl).

Training LoRA (rank 8, alpha 16, `lr=5e-5`, 2 epochs, completion-only loss masking on `yes`/`no`, 296 non-test rows with `find_sink_line` grounding) on a T4 GPU took `275.9s`:

- Vul4J AUC improved from `0.5444` (earlier full-sequence `r=16, lr=1e-4` run) to `0.7000` (`P@90R = 0.5000`), beating Heuristic (`0.5778`) and Kev-4B (`0.6667`).
- L3 AUC improved from `0.5988` to `0.6520` (`0.6014` within-rule AUC, `P@90R = 0.1971`, `+0.0541` swap delta).
- L2 within-rule AUC reached `0.6310` (`+0.0770` swap delta, `0.5872` overall AUC).
- L0 and L1 overall AUC remain lower than zero-shot (`0.5282` and `0.5390`) because [prepare_contrastive_dataset.py](prepare_contrastive_dataset.py) still extracts short raw diff hunks instead of full enclosing methods.

## 4. Comparative numbers

| Benchmark Level | Heuristic Baseline | Kev-4B (4B Dense) | d1-3B Zero-Shot | d1-3B Targeted Prompt | d1-3B Contrastive LoRA |
|---|---|---|---|---|---|
| L0 Location Proxy AUC | 0.5886 | 0.7521 | 0.6941 | 0.6098 | 0.5282 |
| L0 Within-Rule AUC | 0.5000 | 0.4612 | 0.4297 | 0.5986 | 0.4728 |
| L0 Swap Delta | N/A | +0.0180 | +0.0202 | +0.0749 | +0.0396 |
| L1 Clean Hunk AUC | 0.5220 | 0.6612 | 0.6672 | 0.5937 | 0.5390 |
| L2 Stored + CWE AUC | 0.6223 | 0.7594 | 0.7861 | 0.5843 | 0.5872 |
| L2 Within-Rule AUC | 0.5000 | 0.4820 | 0.4571 | 0.6321 | 0.6310 |
| L3 Clean Hunk + CWE AUC | 0.5235 | 0.7167 | 0.8372 | 0.6261 | 0.6520 |
| L3 Within-Rule AUC | 0.5000 | 0.5100 | 0.5495 | 0.5761 | 0.6014 |
| L3 Swap Delta | N/A | +0.0210 | +0.0150 | +0.0462 | +0.0541 |
| Vul4J Real CVEs AUC (n=14) | 0.5778 | 0.6667 | 0.8000 | N/A | 0.7000 |

Note on deployment readiness:
With `P@90R = 0.1884` on L3, catching 90% of real bugs still leaves over 81% false positives in the accepted queue.
And while single-pass forward scoring on T4 takes ~12-14 ms, end-to-end per-row timing recorded in [d1_targeted_identity_ghsa.jsonl](d1_targeted_identity_ghsa.jsonl) and [d1_lora_identity_ghsa.jsonl](d1_lora_identity_ghsa.jsonl) averages `626 ms` and `484 ms` respectively due to tokenization and Python loop overhead.

## 5. Reproduction

Run the evaluation suite locally with:

```bash
uv run python audit/evaluate_d1.py
```
