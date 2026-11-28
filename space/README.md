---
title: d1-triage
emoji: D1
colorFrom: indigo
colorTo: purple
sdk: gradio
sdk_version: 6.32.0
app_file: app.py
pinned: false
license: apache-2.0
short_description: Java SAST alert triage preview with sink grounding
---

# d1-triage

Gradio demo for Java static-analysis alert triage with sink-line grounding and the keyword heuristic fallback (`D1_TRIAGE_MOCK=true` by default on CPU Spaces).
On the offline GHSA evaluation set (174 rows), the full-method contrastive LoRA checkpoint reaches `0.8339` L3 ROC-AUC and `0.6027` same-rule L3 AUC (see `audit/TECHNICAL_REPORT.md`).
