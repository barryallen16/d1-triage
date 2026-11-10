# Audit and benchmark evaluation suite

This directory contains the audit scripts, benchmark predictions, patch ground-truth data, and technical report for the Liquid AI d1-3B static analysis triage benchmark.

## Core entry points

- `evaluate_d1.py`: One-command benchmark evaluation table across all four gate levels (L0 to L3) and Vul4J.
- `compare_all_phases.py`: Side-by-side comparison across heuristic baseline, targeted sink prompt, hybrid criteria, and contrastive LoRA.
- `test_whole_suite.py`: Comprehensive 19-test verification suite checking data integrity, prediction completeness, sink finding, and CLI operation.
- `test_ensemble.py`: Ensembling sensitivity sweep testing blends of rule priors and code discrimination scores.

## Research report

- `TECHNICAL_REPORT.md`: Full technical report detailing methodology, statement anchoring, contrastive LoRA tuning, and systems benchmarks.
- `adjudication_packet.md`: Manual ground-truth adjudication notes analyzing 64 real-world CVE patches against Semgrep findings.
- `adjudication.json`: Machine-readable verdicts and rationale for all adjudicated findings.

## Training and dataset generation

- `d1_contrastive_lora_train.py`: Standalone LoRA fine-tuning script using real-world pre- and post-fix git diff pairs.
- `prepare_contrastive_dataset.py`: Extracts balanced vulnerable and patched method pairs from held-out advisory patches.
- `fetch_heldout_patches.py`: Downloads patch files for held-out repositories.
- `contrastive_train.jsonl`: Curated training set of 416 balanced Java vulnerability and fix pairs.

## Benchmark prediction artifacts

- `d1_targeted_identity_ghsa.jsonl`: Predictions with statement-level sink grounding on the 174-row GHSA set.
- `d1_targeted_swap_ghsa.jsonl`: Predictions under paired rule-swap controls on GHSA.
- `d1_lora_identity_ghsa.jsonl`: Predictions from the contrastive LoRA adapter on GHSA.
- `d1_lora_swap_ghsa.jsonl`: Predictions from the contrastive LoRA adapter under rule-swap controls.
- `d1_lora_identity_vul4j.jsonl`: Predictions from the contrastive LoRA adapter on the 14-row Vul4J set.

## Patch datasets

- `patches/`: 67 patch diff files for evaluated GHSA advisories.
- `heldout_patches/`: 40 patch diff files used strictly for contrastive training.
