# Run d1-triage locally

This guide covers running the d1-triage developer tool on CPU or GPU, and running the legacy scoring pipeline.

## 1. Local run with d1-3B

The main triage tool uses Liquid AI's d1-3B foundation model to score static analysis findings.

```bash
# Set up environment
uv sync

# Run interactive demo with mock engine (no model download required)
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

Build and run in a container with Java 17 and Semgrep pre-installed:

```bash
# Build image
docker build -t d1-triage .

# Run demo
docker run --rm d1-triage --demo --mock

# Scan a local project directory mounted into the container
docker run --rm -v $(pwd)/my-project:/src d1-triage --scan /src/findings.json
```

## 3. Heuristic baseline pipeline

The heuristic and baseline pipeline remains available via `python -m triage.cli`:

```bash
# Heuristic ranking (no model required)
uv run python -m triage.cli path/to/java/project --scorer heuristic --json

# QLoRA model (requires CUDA and model extras)
uv run python -m triage.cli path/to/java/project --adapter path/to/adapter --json
```
