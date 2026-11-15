---
title: d1-triage
emoji: ⚡
colorFrom: indigo
colorTo: purple
sdk: gradio
sdk_version: 6.32.0
app_file: app.py
pinned: false
license: apache-2.0
short_description: Liquid AI d1-3B SAST alert triage engine on CPU
---

# d1-triage

Sub-second static analysis security alert triage using **Liquid AI d1-3B on CPU**.

## Specifications
* **Runtime**: Hugging Face Spaces (CPU)
* **Model**: `LiquidAI/d1-3B` (CPU Execution)
* **Inference**: Single-pass forward prefill on commodity CPU
* **Accuracy**: 64.3% false alarm suppression with 0 missed vulnerabilities on real CVEs
