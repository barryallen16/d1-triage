set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
REPO="barryallen16/d1-triage"

stage="$(mktemp -d)"
cp data/triage/triage_train.jsonl data/triage/triage_val.jsonl \
   data/triage/triage_test.jsonl data/triage/triage_all.jsonl \
   data/triage/triage_sample200.jsonl "$stage/"
cp model-evaluation/juliet-heldout-1000-neutral-v2.csv "$stage/"
tar -czf /tmp/triage-v1.tar.gz -C "$stage" .
rm -rf "$stage"

stage="$(mktemp -d)"
cp data/legacy/legacy_clean_train.jsonl data/legacy/legacy_clean_val.jsonl "$stage/"
cp model-evaluation/juliet-heldout-1000-neutral-v2.csv "$stage/"
tar -czf /tmp/legacy-v1.tar.gz -C "$stage" .
rm -rf "$stage"

hf upload "$REPO" /tmp/triage-v1.tar.gz triage-v1.tar.gz --type dataset
hf upload "$REPO" /tmp/legacy-v1.tar.gz legacy-v1.tar.gz --type dataset
