<p align="center">
  <img src="d1-triage.svg" alt="d1-triage" width="400">
</p>

<p align="center">
  <a href="https://huggingface.co/barryallen16/d1-3B-java-vuln-triage"><img src="https://img.shields.io/badge/%F0%9F%A4%97%20Model-d1--3B--java--vuln--triage-yellow?style=flat-square" alt="Hugging Face Model"></a>
  <a href="https://huggingface.co/datasets/barryallen16/d1-triage"><img src="https://img.shields.io/badge/%F0%9F%A4%97%20Dataset-d1--triage-blue?style=flat-square" alt="Hugging Face Dataset"></a>
  <a href="https://barryallen16.github.io/d1-triage/"><img src="https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-success?style=flat-square" alt="Live Demo"></a>
  <a href="audit/TECHNICAL_REPORT.md"><img src="https://img.shields.io/badge/Audit-Technical%20Report-purple?style=flat-square" alt="Technical Report"></a>
</p>

# d1-triage: Static Analysis Alert Triage with Liquid AI d1-3B

Static analysis scanners flag Java security patterns with high recall, but false positives often exceed 70%.
`d1-triage` benchmarks Liquid AI's hybrid `d1-3B` model on ranking Semgrep alerts by exploitability, and ships a local CLI with an AST heuristic mode for fast dry runs.

---

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
# 1. Interactive demo: path traversal vs guarded XML parser
d1-triage --demo --mock

# 2. Triage a Semgrep report and export prioritized JSON
d1-triage --scan semgrep-findings.json --mock --output triage-report.json

# 3. Sample 5 benchmark alerts
d1-triage --benchmark ghsa --limit 5 --mock
```

Note: The local CLI and GitHub Pages playground use the AST heuristic baseline (`--mock`) for instant feedback.
Real `d1-3B` logit scoring runs via the Hugging Face model/training scripts in `audit/`.

---

## Benchmark leaderboard

Evaluated on 174 real-world Java alerts across 68 GitHub advisories (GHSA) and 14 alerts across 126 Vul4J benchmark repositories (5 TP, 9 FP).
All numbers below come directly from [audit/evaluate_d1.py](audit/evaluate_d1.py), [audit/compare_all_phases.py](audit/compare_all_phases.py), and [audit/score-d1_champion.json](audit/score-d1_champion.json).

| Model / Configuration | Architecture | Verified Patch AUC (L3) | Same-Rule AUC (L3) | L0 Swap Delta | Vul4J AUC (n=14) | End-to-End Latency (T4) |
|---|---|---|---|---|---|---|
| **Semgrep Baseline** | Scanner rules | 0.5235 | 0.5000 | N/A | 0.5778 | <1 ms (CPU) |
| **Kev-4B** | 4B Transformer | 0.7167 | 0.5100 | +0.0180 | 0.6667 | ~85 ms (fwd) / 12.8 GB VRAM |
| **d1-3B Zero-Shot** | 3B Hybrid SSM | **0.8372** | 0.5495 | +0.0202 | **0.8000** | ~12 ms (fwd) / 6.2 GB VRAM |
| **d1-3B Targeted Prompt** | 3B Hybrid SSM | 0.6261 | 0.5761 | +0.0749 | N/A | 626 ms avg (full loop) |
| **d1-3B Contrastive LoRA** | 3B Hybrid SSM | 0.6520 | 0.6014 | +0.0396 | 0.7000 | ~414 ms avg (T4 loop) |

*Definitions*:
Verified Patch (L3) requires the finding line to sit inside a verified security fix hunk and match the advisory CVE CWE (28 of 174 rows).
Same-Rule AUC measures ranking discrimination among alerts sharing the same Semgrep rule.
Swap Delta measures the AUC drop when code windows are shuffled behind identical rules.
The four verification filters (L0 to L3) are detailed in [audit/TECHNICAL_REPORT.md](audit/TECHNICAL_REPORT.md).

---

## Key findings

Zero-shot `d1-3B` reaches `0.8372` L3 AUC mostly by exploiting rule-name priors rather than reading code.
In the GHSA set, `documentbuilderfactory-disallow-doctype-decl-missing` is 91% TP (32/35) while `formatted-sql-string` is 4% TP (1/26), so zero-shot scores `0.4297` within-rule AUC on L0 and barely moves (`+0.0202`) when code windows are swapped.

Injecting `>>> [ALERT LINE X]` at the matched sink line forces code sensitivity, lifting L0 within-rule AUC from `0.4297` to `0.5986` and L0 swap delta to `+0.0749`, though overall L3 AUC drops to `0.6261`.

Fine-tuning on synthetic Juliet cases collapsed real-world generalization (`0.449` within-rule AUC).
Filtering out the 120 test-file rows from [audit/contrastive_train.jsonl](audit/contrastive_train.jsonl) (leaving 296 non-test rows) and training Contrastive LoRA (`r=8`, `lr=5e-5`, 2 epochs) with completion-only loss masking on `yes`/`no` plus `find_sink_line` grounding lifted Vul4J AUC from `0.5444` to `0.7000` (`P@90R = 0.5000`, beating Heuristic `0.5778` and Kev-4B `0.6667`), L3 AUC from `0.5988` to `0.6520` (`0.6014` within-rule AUC), and L2 within-rule AUC to `0.6310`.
Remaining gap: the 296 non-test rows are still short raw diff hunks rather than full enclosing methods, which limits L0/L1 overall AUC (`0.5282` / `0.5390`).
With `P@90R = 0.1971` on L3, the model works as a triage ranker rather than an autonomous filter.

---

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

---

## Published artifacts

| Resource | Platform | Link | Description |
|---|---|---|---|
| **Model Weights** | Hugging Face | [`barryallen16/d1-3B-java-vuln-triage`](https://huggingface.co/barryallen16/d1-3B-java-vuln-triage) | Fine-tuned Liquid AI d1-3B Q8_0 weights (2.87 GB) |
| **Benchmark Dataset** | Hugging Face | [`barryallen16/d1-triage`](https://huggingface.co/datasets/barryallen16/d1-triage) | 174 real-world Java alerts across GHSA & Vul4J census |
| **Interactive Demo** | GitHub Pages | [`barryallen16.github.io/d1-triage`](https://barryallen16.github.io/d1-triage/) | Client-side heuristic playground with sink grounding |
| **Technical Report** | Audit & Notes | [`audit/TECHNICAL_REPORT.md`](audit/TECHNICAL_REPORT.md) | Methodology, rule priors, and failure analysis |
