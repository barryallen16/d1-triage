# d1-triage: local static analysis alert triage CLI

`d1-triage` inspects Java security alerts using statement-level sink marking and an AST heuristic baseline (`--mock`) for fast offline testing.
It reads Semgrep JSON scan reports or the included GHSA and Vul4J benchmark samples and ranks findings by `P(TP)`.

## What it does

- Matches and tags the flagged sink line with `>>> [ALERT LINE n]` via `d1_triage/sink_finder.py`.
- Parses Semgrep JSON reports and expands source context around the flagged line when source files exist on disk.
- Ranks alerts with AST guard checks in `--mock` mode or writes JSON triage reports with `-o`.

## Quick start

Run the built-in two-finding demo (path traversal TP vs guarded XML parser FP):

```bash
python d1_triage.py --demo --mock
```

Scan a project with Semgrep and rank the exported JSON report:

```bash
semgrep scan --config auto --json -o semgrep-report.json
python d1_triage.py --scan semgrep-report.json --mock --output triage-summary.json
```

Sample findings from the GHSA or Vul4J benchmark sets:

```bash
python d1_triage.py --benchmark ghsa --limit 5 --mock
python d1_triage.py --benchmark vul4j --limit 5 --mock
```

Running without `--mock` raises a `RuntimeError` because model weights are not bundled with the standalone CLI.
For real `LiquidAI/d1-3B` scoring, use the scripts under `audit/` or `scripts/test_q8_systemone.py` with a downloaded GGUF file.

## CLI reference

| Flag | Description | Default |
|---|---|---|
| `--demo` | Run built-in two-finding demo | False |
| `--scan <path>` | Path to Semgrep JSON scan report | None |
| `--benchmark <name>` | Sample findings from `ghsa` or `vul4j` | None |
| `--limit <n>` | Number of benchmark findings to inspect | 5 |
| `--cpu` | Force CPU flag in config | Auto-detect |
| `--gpu` | Force CUDA flag in config | Auto-detect |
| `--mock` | Run the AST heuristic baseline with no model download | False |
| `--threshold <f>` | Exploitability decision cutoff | 0.5 |
| `--output <path>` | Export JSON results to path | None |
| `--model <id>` | Hugging Face model ID or local path | LiquidAI/d1-3B |
