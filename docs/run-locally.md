# Run d1-triage locally

This guide covers the `d1-triage` CLI in heuristic mock mode and the `triage` scoring module.

## 1. Local CLI (keyword heuristic mode)

Set up the environment with `uv`:

```bash
uv sync
```

Run the demo, a Semgrep scan report, or benchmark samples using `--mock`:

```bash
uv run python d1_triage.py --demo --mock
uv run python d1_triage.py --scan semgrep-findings.json --mock --output triage-report.json
uv run python d1_triage.py --benchmark ghsa --limit 5 --mock
uv run python d1_triage.py --benchmark vul4j --limit 5 --mock
```

Omitting `--mock` raises a `RuntimeError` because the standalone CLI does not bundle `LiquidAI/d1-3B` weights.

## 2. Docker container

```bash
docker build -t d1-triage .
docker run --rm d1-triage --demo --mock
docker run --rm -v $(pwd)/my-project:/src d1-triage --scan /src/findings.json --mock
```

## 3. Scoring module (`triage.cli`)

`triage.cli` runs the heuristic baseline, a generation scorer, or the Qwen3.5-4B decision scorer.
The model scorers need CUDA and `unsloth`:

```bash
uv run python -m triage.cli path/to/java/project --scorer heuristic --json
uv run python -m triage.cli path/to/java/project --scorer decision --adapter path/to/adapter --json
```
