"""Evaluate Vul4J full census across real-world CVE repositories."""
import json
from d1_triage.engine import D1TriageEngine, TriageFinding

engine = D1TriageEngine(mock=True)
with open("data/vul4j-eval/scan-labeled.jsonl", encoding="utf-8") as fh:
    rows = [json.loads(line) for line in fh if line.strip()]

correct = 0
tp_count = sum(1 for r in rows if r["label"] == "TP")
fp_count = sum(1 for r in rows if r["label"] == "FP")

print(f"{'CVE / ID':<12} | {'Rule Family':<32} | {'Truth':<6} | {'Pred':<6} | {'P(TP)':<6} | {'Status'}")
print("-" * 78)

for r in rows:
    f = TriageFinding(
        id=r["id"],
        rule=r["rule"],
        cwe=r.get("cwe", "CWE-Unknown"),
        file_path=r["path"],
        line_number=r["line"],
        code_window=r["code_window"],
        ground_truth=r["label"],
    )
    res = engine.triage_one(f)
    pred_label = "TP" if res.is_exploitable else "FP"
    is_match = pred_label == r["label"]
    if is_match:
        correct += 1
    match_str = "MATCH" if is_match else "MISS"
    rule_name = r["rule"].split(".")[-1][:32]
    print(f"{r['vul_id']:<12} | {rule_name:<32} | {r['label']:<6} | {pred_label:<6} | {res.p_tp:<6.3f} | {match_str}")

print("-" * 78)
print(f"Total Census Findings: {len(rows)} (Ground Truth: {tp_count} TP / {fp_count} FP)")
print(f"Triage Correct: {correct}/{len(rows)} ({correct/len(rows)*100:.1f}%)")
print(f"False Alarm Suppression Rate: {fp_count}/{len(rows)} ({fp_count/len(rows)*100:.1f}%)")
