# Run d1-triage locally

This guide covers running the `d1-triage` CLI in heuristic mock mode and running the `triage` QLoRA/heuristic scoring module.

## 1. Local CLI (AST heuristic mode)

Set up the environment with `uv`:

```bash
uv sync
```

Run the interactive demo, a Semgrep scan report, or benchmark samples using `--mock`:

```bash
# Run interactive demo with AST heuristic engine
uv run python d1_triage.py --demo --mock

# Triage a Semgrep JSON scan report
uv run python d1_triage.py --scan semgrep-findings.json --mock --output triage-report.json

# Sample real alerts from benchmark sets
uv run python d1_triage.py --benchmark ghsa --limit 5 --mock
uv run python d1_triage.py --benchmark vul4j --limit 5 --mock
```

Passing `mock=False` (omitting `--mock`) raises a `RuntimeError` because the standalone CLI does not bundle `LiquidAI/d1-3B` weights.

## 2. Docker container

Build and run in a container:

```bash
docker build -t d1-triage .
docker run --rm d1-triage --demo --mock
docker run --rm -v $(pwd)/my-project:/src d1-triage --scan /src/findings.json --mock
```

## 3. Scoring module (`triage.cli`)

The `triage` package supports both the heuristic baseline and QLoRA logit scoring (`Qwen/Qwen3.5-4B` via `unsloth`):

```bash
# Heuristic ranking (no GPU required)
uv run python -m triage.cli path/to/java/project --scorer heuristic --json

# QLoRA model (requires CUDA and model extras)
uv run python -m triage.cli path/to/java/project --adapter path/to/adapter --json
```
