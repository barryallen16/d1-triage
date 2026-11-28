# Audit and benchmark evaluation suite

This directory holds benchmark predictions, ground-truth patches, training data builders, and evaluation scripts for the Liquid AI `d1-3B` static analysis triage benchmark.

## Core entry points

- `evaluate_d1.py`: benchmark evaluation table across all four gate levels (L0 to L3) and Vul4J.
- `compare_all_phases.py`: side-by-side comparison of the heuristic baseline, targeted sink prompt, hybrid criteria, and contrastive LoRA.
- `test_whole_suite.py`: 19-test suite covering data integrity, prediction completeness, sink finding, and CLI operation.
- `test_ensemble.py`: ensembling sweep over blends of rule priors and code scores.

## Report and adjudication

- `TECHNICAL_REPORT.md`: label levels, statement anchoring, full-method contrastive LoRA tuning, and benchmarks.
- `adjudication.json`: machine-readable verdicts and rationale for the adjudicated sample.

## Training and dataset generation

- `build_full_method_dataset.py`: extracts 1,643 non-test full enclosing Java methods from 465 held-out commits into `full_method_train.jsonl`.
- `make_kaggle_runs.py`: generates self-contained Kaggle GPU scripts for the logit-readout KL sweeps.
- `d1_contrastive_lora_train.py`: standalone logit-readout LoRA fine-tuning script with KL base-model anchoring.
- `prepare_contrastive_dataset.py`: extracts 416 balanced vulnerable and patched hunk pairs into `contrastive_train.jsonl`.
- `fetch_heldout_patches.py`: downloads patch files for held-out repositories.

## Benchmark prediction artifacts

- `d1_targeted_identity_ghsa.jsonl`: predictions with statement-level sink grounding on the 174-row GHSA set.
- `d1_targeted_swap_ghsa.jsonl`: predictions under paired rule-swap controls on GHSA.
- `d1_lora_identity_ghsa.jsonl`: predictions from the full-method contrastive LoRA adapter on GHSA.
- `d1_lora_swap_ghsa.jsonl`: predictions from the full-method contrastive LoRA adapter under rule-swap controls.
- `d1_lora_identity_vul4j.jsonl`: predictions from the full-method contrastive LoRA adapter on the 14-row Vul4J set.

## Patch datasets

- `patches/`: 67 patch diff files for evaluated GHSA advisories.
- `heldout_patches/`: 40 patch diff files used only for contrastive training.
