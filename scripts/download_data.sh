#!/usr/bin/env bash
# Pull benchmark evaluation sets and dataset packages from HF.
set -e
cd "$(dirname "$0")/.."
mkdir -p data/ghsa-eval data/vul4j-eval
curl -sL https://huggingface.co/datasets/barryallen16/triagemate/resolve/main/ghsa-scan-labeled.jsonl -o data/ghsa-eval/labels.jsonl
curl -sL https://huggingface.co/datasets/barryallen16/triagemate/resolve/main/vul4j-scan-labeled.jsonl -o data/vul4j-eval/scan-labeled.jsonl
