---
license: apache-2.0
task_categories:
- text-classification
language:
- en
configs:
- config_name: vul4j-labeled
  data_files:
  - split: train
    path: vul4j-labeled.jsonl
- config_name: vul4j-scan-labeled
  data_files:
  - split: train
    path: vul4j-scan-labeled.jsonl
- config_name: ghsa-scan-labeled
  data_files:
  - split: train
    path: ghsa-scan-labeled.jsonl
---

# d1-triage Java scan labels

Java static-analysis alerts from Vul4J entries and GitHub advisory fix commits, with a binary TP/FP label.

`vul4j-labeled.jsonl` is the earlier 66-row full-repository scan.
`vul4j-scan-labeled.jsonl` is the current 14-row changed-file scan.
`ghsa-scan-labeled.jsonl` is a 174-row set from GitHub advisory fix commits, used as a second real-world check.

Each row carries the entry ID, rule, CWE, file, line, code window, and the Semgrep severity score used as the no-model baseline.

## Label rule

A finding is a true positive when its reported line overlaps a line changed by the fix, including two lines of context, or falls inside a method the fix changes.
The labels are a location proxy, not proof that the finding is the exact CVE.

## Vul4J changed-file result

The changed-file set has 14 findings across 10 entries: 5 location-proxy true positives and 9 false positives.
It covers every Vul4J entry with a usable patch commit: 126 of 127 checked out and scanned, with test sources excluded.
The Semgrep severity baseline reaches ROC-AUC 0.5778 and precision at 90% recall 0.3571.
LiquidAI d1-3B zero-shot reaches ROC-AUC 0.8000 and precision at 90% recall 0.5556, a gain of 0.2222 AUC.
Kev-4B reaches ROC-AUC 0.6667 and precision at 90% recall 0.4545, a gain of 0.0889 AUC.

The d1 gain survives leave-one-entry-out (never below 0.1250) and the row bootstrap (`P(delta <= 0)` is 0.094).
Kev-4B flips negative when VUL4J-65, VUL4J-83-S, or VUL4J-107-S is dropped, and its Vul4J row bootstrap puts `P(delta <= 0)` at 0.35.

With five positives, the Vul4J ranking result stays small-sample.
Labels are based on overlap with fix hunks or methods and are not human confirmation of vulnerability identity.
The earlier 46-row set mixed full-repository and changed-file scans, so 36 of its rows were findings in files the fix never touched; its numbers are superseded.

## GHSA check

`ghsa-scan-labeled.jsonl` holds 174 findings from 68 fix commits in Maven packages, sampled from the OSV advisory export across 12 CWE families and 314 repositories.
The scan and label pipeline matches Vul4J: changed Java files only, test sources excluded, positive when the finding overlaps a fix hunk or a changed method.

| Scorer | n | ROC-AUC | Precision at 90% recall |
|---|---|---|---|
| Semgrep severity heuristic | 174 | 0.5886 | 0.4885 |
| LiquidAI d1-3B zero-shot | 174 | 0.6941 | 0.4847 |
| LiquidAI d1-3B + criteria | 174 | 0.7028 | 0.5132 |
| Kev-4B | 174 | 0.7521 | 0.6063 |

On the L0 location-proxy labels, zero-shot d1 gains +0.1054 ROC-AUC and loses 0.0038 precision at 90% recall, so the heuristic gate is not beaten there.
The heuristic has only two scores.
90% recall needs 77 positives, and only 59 sit at 0.75, so the cut moves to 0.5 and accepts every row.
Precision there is 85/174 = 0.4885, the heuristic's overall precision.
Ties are accepted whole, so row order cannot change it.
An entry-level bootstrap puts the d1 AUC gain between -0.0952 and +0.3232, with `P(delta <= 0)` at 0.1855.

Adding `criteria` pushes L0 AUC to 0.7028 and `P@90R` to 0.5132, both above the heuristic.
That gain comes from rule-level calibration: weighted within-rule AUC sits at 0.474, below chance.

Of the 85 stored positives, 44 sit on a changed hunk line and 41 sit only inside a touched method.
Under stricter definitions (hunk-only with 44 TP, CWE-matched with 53 TP, or both L3 with 28 TP), zero-shot d1 reaches 0.667 to 0.837 AUC, though rule priors still explain most of that score.

Metadata baselines match both untrained models on L0.
Out-of-fold logistic regression on rule name alone reaches 0.767 AUC, and rule plus file name reaches 0.786 entry-grouped and 0.799 repo-grouped, ahead of d1 at 0.694 and Kev-4B at 0.752.
Under the L1 hunk-only label, that metadata baseline drops to 0.461 entry-grouped and 0.587 repo-grouped.
A swap-window control moves zero-shot within-rule AUC from 0.474 to 0.590 after a global swap and 0.444 after a within-rule swap, showing the unaligned prompt barely reads the code.
