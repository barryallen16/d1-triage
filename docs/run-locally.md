# Run TriageMate locally

This guide covers running the d1-triage developer tool on standard CPU or GPU, as well as accessing legacy scoring pipelines.

## 1. Quick local run (d1-3B)

The primary tool uses Liquid AI's d1-3B foundation model to triage static analysis findings.

```bash
# Set up environment
uv sync

# Run interactive showcase with mock engine (no model download required)
uv run python d1_triage.py --demo --mock

# Triage a Semgrep JSON scan report
uv run python d1_triage.py --scan semgrep-findings.json --output triage-report.json

# Sample real alerts from benchmark sets
uv run python d1_triage.py --benchmark ghsa --limit 5 --mock
uv run python d1_triage.py --benchmark vul4j --limit 5 --mock
```

Install the `model` dependency group when running live model inference with PyTorch:

```bash
uv sync --extra model
uv run python d1_triage.py --scan semgrep-findings.json
```

## 2. Docker container

Build and run in a self-contained Linux container with Java 17 and Semgrep pre-installed:

```bash
# Build image
docker build -t triagemate .

# Run demo showcase
docker run --rm triagemate --demo --mock

# Scan a local project directory mounted into the container
docker run --rm -v $(pwd)/my-project:/src triagemate --scan /src/findings.json
```

## 3. Legacy pipeline (Phase 1 QLoRA / Heuristic)

The original Phase 1 research tools remain available via the `triagemate-legacy` command:

```bash
# Heuristic ranking (no model required)
uv run triagemate-legacy path/to/java/project --scorer heuristic --json

# Legacy QLoRA model (requires CUDA and model extras)
uv run triagemate-legacy path/to/java/project --adapter path/to/adapter --json
```
