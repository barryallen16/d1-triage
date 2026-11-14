set -e
cd "$(dirname "$0")/.."
mkdir -p data/ghsa-eval data/vul4j-eval
curl -sL https://huggingface.co/datasets/barryallen16/d1-triage/resolve/main/ghsa-scan-labeled.jsonl -o data/ghsa-eval/labels.jsonl
curl -sL https://huggingface.co/datasets/barryallen16/d1-triage/resolve/main/vul4j-scan-labeled.jsonl -o data/vul4j-eval/scan-labeled.jsonl
