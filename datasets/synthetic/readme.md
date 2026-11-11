# Synthetic dataset generation prompt

This document records the prompt template used during Phase 1 for LLM-assisted synthetic vulnerability dataset creation.
As documented in [leak-audit.md](file:///C:/Users/rjaya/Desktop/currently-working-projects/triagemate/notes/leak-audit.md) and [TECHNICAL_REPORT.md](file:///C:/Users/rjaya/Desktop/currently-working-projects/triagemate/audit/TECHNICAL_REPORT.md), models trained purely on synthetic samples suffered from distribution collapse on real-world vulnerabilities.
This led to the contrastive git-diff fine-tuning strategy adopted in Phase 3.

## Specification

- Target: Java source snippets demonstrating vulnerable and secure coding constructs.
- Categories: OWASP Top 10, SANS Top 25, CWE Top 25.
- Class balance: 60% vulnerable, 40% secure.
- Output format: JSONL records containing `code`, `classification`, and `vulnerability_type`.

## Prompt template

```text
Act as a Java security expert specializing in vulnerability classification.
Generate a diverse set of Java code samples in JSONL format that demonstrate both vulnerable and secure coding practices.

For each sample, provide:
- Java code (40 to 200 lines)
- Classification as VULNERABLE or NOT_VULNERABLE
- Specific vulnerability type (CWE identifier or "safe")

Requirements:
- Cover injection, broken authentication, sensitive data exposure, XXE, broken access control, security misconfiguration, XSS, and insecure deserialization.
- Maintain varied contexts (web services, microservices, libraries).
- Output JSON format:
  {"code": "...", "classification": "...", "vulnerability_type": "..."}
```
