<p align="center">
  <img src="d1-triage.svg" alt="d1-triage" width="400">
</p>

<p align="center">
  <a href="https://huggingface.co/barryallen16/d1-3B-java-vuln-triage"><img src="https://img.shields.io/badge/Model-d1--3B--java--vuln--triage-yellow?style=flat-square" alt="Hugging Face Model"></a>
  <a href="https://huggingface.co/datasets/barryallen16/d1-triage"><img src="https://img.shields.io/badge/Dataset-d1--triage-blue?style=flat-square" alt="Hugging Face Dataset"></a>
  <a href="https://barryallen16.github.io/d1-triage/"><img src="https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-success?style=flat-square" alt="Live Demo"></a>
  <a href="audit/TECHNICAL_REPORT.md"><img src="https://img.shields.io/badge/Audit-Technical%20Report-purple?style=flat-square" alt="Technical Report"></a>
</p>

# d1-triage: Static analysis alert triage with Liquid AI d1-3B

Static analysis scanners flag Java security patterns with high recall, and false positives often exceed 70%.
`d1-triage` benchmarks Liquid AI's hybrid `d1-3B` model on ranking Semgrep alerts by exploitability and includes a local CLI with an AST heuristic mode for dry runs.

## Quickstart

Install with `uv` (recommended):

```bash
uv tool install git+https://github.com/barryallen16/d1-triage.git
```

Or with `pip`:

```bash
pip install git+https://github.com/barryallen16/d1-triage.git
```

Run the CLI locally in heuristic mock mode (`--mock`, no model download required):

```bash
d1-triage --demo --mock
d1-triage --scan semgrep-findings.json --mock --output triage-report.json
d1-triage --benchmark ghsa --limit 5 --mock
```

The local CLI and GitHub Pages demo run the AST heuristic baseline (`--mock`) for offline feedback.
Logit scoring with `d1-3B` runs through the Hugging Face model and the training scripts in `audit/`.

## Benchmark leaderboard

Evaluated on 174 real-world Java alerts across 68 GitHub advisories (GHSA) and 14 alerts across 126 Vul4J benchmark repositories (5 TP, 9 FP).
Numbers below come from [audit/evaluate_d1.py](audit/evaluate_d1.py), [audit/compare_all_phases.py](audit/compare_all_phases.py), and [audit/score-d1_champion.json](audit/score-d1_champion.json).

| Model / Configuration | Architecture | Verified Patch AUC (L3) | Same-Rule AUC (L3) | L0 Swap Delta | Vul4J AUC (n=14) | End-to-End Latency (T4) |
|---|---|---|---|---|---|---|
| Semgrep Baseline | Scanner rules | 0.5235 | 0.5000 | N/A | 0.5778 | <1 ms (CPU) |
| Kev-4B | 4B Transformer | 0.7167 | 0.5100 | +0.0180 | 0.6667 | ~85 ms (fwd) |
| d1-3B Zero-Shot | 3B Hybrid SSM | 0.8372 | 0.5495 | +0.0202 | 0.8000 | ~12 ms (fwd) / 6.2 GB VRAM |
| d1-3B Targeted Prompt | 3B Hybrid SSM | 0.6261 | 0.5761 | +0.0749 | N/A | 626 ms avg (loop) |
| d1-3B Contrastive LoRA (v2) | 3B Hybrid SSM | 0.8339 | 0.6027 | +0.0365 | 0.5222 | 456 ms avg (T4 loop) |

Verified Patch (L3) requires the finding line to sit inside a verified security fix hunk and match the advisory CVE CWE (28 of 174 rows).
Same-Rule AUC measures ranking accuracy among alerts sharing the same Semgrep rule.
Swap Delta measures the AUC drop when code windows are shuffled behind identical rules.
The four verification filters (L0 to L3) are documented in [audit/TECHNICAL_REPORT.md](audit/TECHNICAL_REPORT.md).

## Key findings

Zero-shot `d1-3B` reaches `0.8372` L3 AUC mostly by using rule-name priors.
In the GHSA set, `documentbuilderfactory-disallow-doctype-decl-missing` is 91% TP (32/35) while `formatted-sql-string` is 4% TP (1/26), so zero-shot scores `0.4297` within-rule AUC on L0 and moves `+0.0202` when code windows are swapped.

Adding `>>> [ALERT LINE X]` at the matched sink line forces code sensitivity, lifting L0 within-rule AUC from `0.4297` to `0.5986` and L0 swap delta to `+0.0749`, though overall L3 AUC drops to `0.6261`.

Fine-tuning on synthetic Juliet cases hurt real-world transfer (`0.449` within-rule AUC).
Naive short-hunk LoRA training (`r=16`, `lr=1e-4`, `line=0`) also lowered overall L3 AUC (`0.5988`) and Vul4J (`0.5444`).
Building a `1,643`-row full-method dataset from `465` held-out commits ([audit/full_method_train.jsonl](audit/full_method_train.jsonl)) and training `d1-3B` with a 2-class `yes`/`no` logit readout loss (`3x` Semgrep upweighting, `KL=0.2` base anchor, `2` epochs) lifted GHSA L3 AUC to `0.8339` (`+0.2351` over naive LoRA, beating `Kev-4B` at `0.7167`), L2 AUC to `0.7977`, L0 AUC to `0.7119`, L3 `P@90R` to `0.3023` (nearly double the heuristic's `0.1609`), and L3 swap delta to `+0.0724` (`0.6027` L3 within-rule AUC).
A higher KL anchor (`KL=0.5`, `1` epoch) trades peak GHSA L3 AUC (`0.7083`) for stronger out-of-distribution retention on Vul4J (`0.6889`, `P@90R = 0.5556`) and L2 within-rule separation (`0.6595`).
With `P@90R = 0.3023` on L3, the model fits triage ranking, not autonomous suppression.

## Reproduction

Calculate GHSA (Targeted Prompt, Contrastive LoRA) and Vul4J metrics on CPU in under 0.2 seconds:

```bash
uv run python audit/evaluate_d1.py
```

Run the 19-test audit verification suite and 51-test unit suite:

```bash
uv run python audit/test_whole_suite.py
uv run python -m pytest -q
```

## Published artifacts

| Resource | Platform | Link | Description |
|---|---|---|---|
| Model Weights | Hugging Face | [`barryallen16/d1-3B-java-vuln-triage`](https://huggingface.co/barryallen16/d1-3B-java-vuln-triage) | Fine-tuned Liquid AI d1-3B weights and artifacts |
| Benchmark Dataset | Hugging Face | [`barryallen16/d1-triage`](https://huggingface.co/datasets/barryallen16/d1-triage) | 174 real-world Java alerts across GHSA and 14 across Vul4J |
| Interactive Demo | GitHub Pages | [`barryallen16.github.io/d1-triage`](https://barryallen16.github.io/d1-triage/) | Client-side heuristic playground with sink grounding |
| Technical Report | Audit & Notes | [`audit/TECHNICAL_REPORT.md`](audit/TECHNICAL_REPORT.md) | Gate definitions, rule priors, and failure analysis |
