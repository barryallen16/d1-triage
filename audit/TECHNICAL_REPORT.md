# Static Analysis Alert Triage with Liquid AI d1-3B

I pulled 174 Semgrep alerts from 68 CVE-associated GitHub advisories and 14 alerts from 126 Vul4J repositories, labelled them four ways, and spent most of the work checking whether the model reads code or just rule names.
The first number looked good: zero-shot `d1-3B` scored `0.8372` L3 AUC.
Most of that came from rule base rates, not from the flagged line.

Scanners such as Semgrep flag unsafe Java patterns with high recall, and false-positive rates often exceed 70%.
A language model can cut the manual review time, but standard benchmarks label an alert at file or method level, which does not show whether the flagged line sits in the security patch.
Two failure modes showed up: shortcut learning from unaligned line numbers, and distribution mismatch during short-hunk fine-tuning.

## 1. Label levels and audit findings

A standard benchmark calls an alert a true positive when it falls anywhere inside a file or method touched by a security commit (Level 0, location proxy).
That adds label noise, because security commits also modify build files, tests, and unrelated helpers.

I split the 174 GHSA findings into four stricter label levels:

- L0 (Location proxy): finding is in any method touched by the vulnerability commit (85 TP of 174 rows).
- L1 (Hunk only): finding line sits inside a modified fix hunk (44 TP of 174 rows).
- L2 (Stored plus CWE): finding rule CWE matches the advisory CVE CWE (53 TP of 174 rows).
- L3 (Hunk plus CWE): finding line is inside the fix hunk and matches the CVE CWE (28 TP of 174 rows).

Zero-shot `d1-3B` scored `0.8372` L3 AUC, `0.4297` L0 within-rule AUC, and `+0.0202` swap-window delta.
Rule base rates in the dataset are heavily skewed, with `documentbuilderfactory-disallow-doctype-decl-missing` at 91% L0 TP and `formatted-sql-string` at 4% L0 TP, so predicting from rule names alone yields a high overall AUC.
Separately, Semgrep reports 1-based file line numbers while the snippet extractor passed unnumbered method bodies, so the model could not tell which statement triggered the alert.

## 2. Statement-level sink grounding

To anchor the model on the flagged statement, [sink_finder.py](../d1_triage/sink_finder.py) matches the rule's sink pattern and tags that line in the prompt:

```java
>>> [ALERT LINE 317]: transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

Under paired rule-swap controls (shuffling code windows within the same rule family):

- L0 within-rule AUC rises from `0.4297` to `0.5986`, and the bootstrap share below random chance drops from `70.7%` to `8.9%`.
- L2 within-rule AUC rises from `0.4571` to `0.6321`.
- Swap delta stays positive at all four levels (`+0.0749` on L0, `+0.0468` on L1, `+0.0780` on L2, `+0.0462` on L3), which means the model reads the tagged Java code.
- Overall L3 AUC drops from `0.8372` to `0.6261`, because the model relies less on rule-name priors.

## 3. Contrastive fine-tuning and full-method training

Fine-tuning on synthetic Juliet cases hurt real-world transfer (`0.449` within-rule AUC), because Juliet uses artificial `bad()` and `good()` names.
To avoid leakage, I first extracted 40 held-out advisory patches with zero overlap against the 68 evaluation advisories, producing 208 pre-fix (TP) and 208 post-fix (FP) short-hunk pairs in [contrastive_train.jsonl](contrastive_train.jsonl).
Naive SFT LoRA on those short hunks dropped L3 AUC to `0.5988` and Vul4J AUC to `0.5444`.

To match the evaluation input structure, [build_full_method_dataset.py](build_full_method_dataset.py) checked out `465` leak-free held-out commits from the OSV Maven export, ran Semgrep, and extracted `1,643` non-test full enclosing Java methods (`797` TP / `846` FP across `729` pre/post pairs and `185` direct Semgrep findings) into [full_method_train.jsonl](full_method_train.jsonl).

Replacing full-vocabulary SFT loss with a 2-class cross-entropy loss over `d1-3B`'s `YES_FORMS` and `NO_FORMS` answer-slot logits, plus a KL anchor toward the base model (`KL_WEIGHT = 0.2`, `3x` Semgrep upweighting, `2` epochs, `r=8`, `lr=3e-5`), produced the champion GHSA checkpoint:

- L3 Verified Patch AUC reached `0.8339` (`+0.3104` over the heuristic's `0.5235`, `+0.1172` over Kev-4B's `0.7167`), with `0.6027` within-rule AUC, `+0.0724` swap delta, and `0.3023` `P@90R` (up from `0.1609` for the heuristic and `0.1806` for the targeted prompt).
- L2 AUC reached `0.7977` (`P@90R = 0.4752`), L1 AUC `0.6680`, and L0 AUC `0.7119`.
- Vul4J AUC (`n=14`) was `0.5222`, because [full_method_train.jsonl](full_method_train.jsonl) lacks the crypto and SSL patterns present in Vul4J. A stronger KL anchor (`KL_WEIGHT = 0.5`, `r=16`, `1` epoch) kept Vul4J at `0.6889` (`P@90R = 0.5556`) and L2 within-rule AUC at `0.6595`, with `0.7083` L3 AUC.

## 4. Benchmark numbers

| Benchmark Level | Heuristic Baseline | Kev-4B (4B Dense) | d1-3B Zero-Shot | d1-3B Targeted Prompt | d1-3B Contrastive LoRA (v2) |
|---|---|---|---|---|---|
| L0 Location Proxy AUC | 0.5886 | 0.7521 | 0.6941 | 0.6098 | 0.7119 |
| L0 Within-Rule AUC | 0.5000 | 0.4612 | 0.4297 | 0.5986 | 0.4308 |
| L0 Swap Delta | N/A | +0.0180 | +0.0202 | +0.0749 | +0.0365 |
| L1 Clean Hunk AUC | 0.5220 | 0.6612 | 0.6672 | 0.5937 | 0.6680 |
| L2 Stored + CWE AUC | 0.6223 | 0.7594 | 0.7861 | 0.5843 | 0.7977 |
| L2 Within-Rule AUC | 0.5000 | 0.4820 | 0.4571 | 0.6321 | 0.5560 |
| L3 Clean Hunk + CWE AUC | 0.5235 | 0.7167 | 0.8372 | 0.6261 | 0.8339 |
| L3 Within-Rule AUC | 0.5000 | 0.5100 | 0.5495 | 0.5761 | 0.6027 |
| L3 Swap Delta | N/A | +0.0210 | +0.0150 | +0.0462 | +0.0724 |
| Vul4J Real CVEs AUC (n=14) | 0.5778 | 0.6667 | 0.8000 | N/A | 0.5222 |

These numbers set the deployment limit.
At `P@90R = 0.3023` on L3, catching 90% of verified bugs still leaves roughly 70% false positives in the accepted queue.
A single-pass forward score on a T4 takes about `12 ms`, but the end-to-end per-row timing recorded in [d1_targeted_identity_ghsa.jsonl](d1_targeted_identity_ghsa.jsonl) and [d1_lora_identity_ghsa.jsonl](d1_lora_identity_ghsa.jsonl) averages `626.1 ms` and `456.4 ms`, because of tokenization and the Python loop.

## 5. Reproduction

```bash
uv run python audit/evaluate_d1.py
```
