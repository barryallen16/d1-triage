"""Upload Liquid AI d1-3B Java Vulnerability Triage benchmark & artifacts to Hugging Face."""
from pathlib import Path
from huggingface_hub import HfApi

REPO_ID = "barryallen16/d1-3B-java-vuln-triage"
AUDIT_DIR = Path(__file__).resolve().parent

MODEL_CARD = """---
license: apache-2.0
tags:
- static-analysis
- security
- vulnerability-detection
- sast
- liquid-ai
- d1-3b
- java
- semgrep
base_model: LiquidAI/d1-3B
pipeline_tag: text-classification
---

# Liquid AI d1-3B: Java Static Analysis Alert Triage

Benchmark artifacts, evaluation scripts, and full-method contrastive LoRA training code for ranking Java Semgrep alerts with Liquid AI `d1-3B`.

Evaluated on 174 real-world Java findings across 68 GitHub advisories (GHSA) and 14 findings across 126 Vul4J repositories (5 TP, 9 FP).

## Benchmark leaderboard

| Model / Variant | Architecture | L0 AUC | L0 Within-Rule AUC | L0 Swap Delta | L2 AUC | L2 Within-Rule AUC | L3 Verified Patch AUC | L3 Within-Rule AUC | Vul4J AUC (n=14) |
|---|---|---|---|---|---|---|---|---|---|
| Heuristic Baseline | Scanner rules | 0.5886 | 0.5000 | N/A | 0.6223 | 0.5000 | 0.5235 | 0.5000 | 0.5778 |
| Kev-4B | 4B Dense Transformer | 0.7521 | 0.4612 | +0.0180 | 0.7594 | 0.4820 | 0.7167 | 0.5100 | 0.6667 |
| d1-3B Zero-Shot (Audit) | 3B Hybrid SSM | 0.6941 | 0.4297 | +0.0202 | 0.7861 | 0.4571 | 0.8372 | 0.5495 | 0.8000 |
| d1-3B Targeted Prompt | 3B Hybrid SSM | 0.6098 | 0.5986 | +0.0749 | 0.5843 | 0.6321 | 0.6261 | 0.5761 | N/A |
| d1-3B Contrastive LoRA (v2) | 3B Hybrid SSM | 0.7119 | 0.4308 | +0.0365 | 0.7977 | 0.5560 | 0.8339 | 0.6027 | 0.5222 |

## Summary

- On GHSA L3 (alert inside a verified fix hunk and matching CVE CWE, 28 of 174 rows), full-method Contrastive LoRA v2 trained on 1,643 methods from 465 held-out commits reaches `0.8339` AUC (`0.3023` P@90R) vs `0.7167` for Kev-4B and `0.5235` for the heuristic baseline.
- Within the same Semgrep rule family, Contrastive LoRA v2 reaches `0.6027` L3 AUC with `+0.0724` L3 rule-swap delta, showing code sensitivity on verified fix hunks.
- Mean end-to-end T4 loop time recorded in `d1_lora_identity_ghsa.jsonl` is `456 ms` per row (~12 ms single-pass forward score).
- Because L3 `P@90R` is `0.3023` and Vul4J LoRA AUC is `0.5222`, this checkpoint fits alert queue ranking, not autonomous suppression.

## Quickstart

```python
import torch
from transformers import AutoModel

model = AutoModel.from_pretrained("LiquidAI/d1-3B", trust_remote_code=True, torch_dtype=torch.float16).cuda()

QUESTION = "Is this static-analysis warning a real, exploitable security bug at the flagged sink (marked with >>>) in the code below? Answer yes only if untrusted input reaches this specific sink without an effective guard."
CRITERIA = {
    "true": "Untrusted input reaches the flagged sink marked with '>>>', and no effective validation, escaping, or containment check neutralizes it in the code.",
    "false": "The flagged sink is protected by guards/validation, input is from a trusted or static source, or the pattern is safe or style-only.",
}
QUESTIONS = {"tp": {"type": "noul", "instructions": QUESTION, "criteria": CRITERIA}}

state = \"\"\"Rule: java.lang.security.audit.path-traversal
CWE: CWE-22
File: FileServer.java
Flagged Line: 45

Java (Flagged sink marked with >>>):
```java
public File getRequestedReport(String userReportName) {
    File baseDir = new File("/var/reports");
>>> [ALERT LINE 45]: File targetFile = new File(baseDir, userReportName);
    return targetFile;
}
```\"\"\"

with torch.inference_mode():
    result = model.system_one_batch([(state, QUESTIONS)])
p_tp = float(result[0]["answers"]["tp"]["noul"])
print(f"Exploitability Probability: {p_tp:.4f}")
```

## Local reproduction

```bash
uv run python audit/evaluate_d1.py
```
"""


def main():
    api = HfApi()
    print(f"Uploading artifacts to Hugging Face: {REPO_ID}...")

    api.upload_file(
        path_or_fileobj=MODEL_CARD.encode("utf-8"),
        path_in_repo="README.md",
        repo_id=REPO_ID,
        repo_type="model",
        commit_message="add model card and benchmark leaderboard",
    )
    print("  [Uploaded] README.md")

    files_to_upload = [
        ("full_method_train.jsonl", "full_method_train.jsonl"),
        ("contrastive_train.jsonl", "contrastive_train.jsonl"),
        ("d1_lora_identity_ghsa.jsonl", "d1_lora_identity_ghsa.jsonl"),
        ("d1_lora_swap_ghsa.jsonl", "d1_lora_swap_ghsa.jsonl"),
        ("d1_lora_identity_vul4j.jsonl", "d1_lora_identity_vul4j.jsonl"),
        ("d1_targeted_identity_ghsa.jsonl", "d1_targeted_identity_ghsa.jsonl"),
        ("evaluate_d1.py", "evaluate_d1.py"),
        ("d1_contrastive_lora_train.py", "d1_contrastive_lora_train.py"),
        ("score-d1_champion.json", "score-d1_champion.json"),
        ("TECHNICAL_REPORT.md", "TECHNICAL_REPORT.md"),
    ]

    for local_name, repo_name in files_to_upload:
        p = AUDIT_DIR / local_name
        if p.exists():
            api.upload_file(
                path_or_fileobj=str(p),
                path_in_repo=repo_name,
                repo_id=REPO_ID,
                repo_type="model",
                commit_message=f"upload {repo_name}",
            )
            print(f"  [Uploaded] {repo_name}")

    print(f"\nUploaded artifacts to: https://huggingface.co/{REPO_ID}")


if __name__ == "__main__":
    main()
