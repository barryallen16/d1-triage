import json
import os
import sys
from pathlib import Path
import numpy as np

AUDIT_DIR = Path(__file__).resolve().parent
REPO_ROOT = Path(os.environ.get("D1_TRIAGE_ROOT", str(AUDIT_DIR.parent if AUDIT_DIR.name == "audit" else AUDIT_DIR)))
AUDIT = REPO_ROOT / "audit" if (REPO_ROOT / "audit").exists() else REPO_ROOT / "work" / "audit"
DATA = REPO_ROOT / "data" if (REPO_ROOT / "data").exists() else REPO_ROOT / "work" / "data"

sys.path.insert(0, str(AUDIT))
import baselines as B
import sensitivity as S

ghsa_path = DATA / "ghsa-eval" / "labels.jsonl"
relabel_path = AUDIT / "relabel.json"
ghsa_rows = S.read(str(ghsa_path))
relabel = {r["id"]: r for r in json.loads(relabel_path.read_text(encoding="utf-8"))}
strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])} for r in ghsa_rows])
hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in ghsa_rows])
stored = np.array([r["label"] == "TP" for r in ghsa_rows])
defs = {
    "L0": stored.astype(int),
    "L1": hunk.astype(int),
    "L2": (stored & strict).astype(int),
    "L3": (hunk & strict).astype(int),
}
ent = np.array([r["vul_id"] for r in ghsa_rows])
rules = np.array([r["rule"].split(".")[-1] for r in ghsa_rows])
base = np.array([float(r["p_tp"]) for r in ghsa_rows])

def load_p(path):
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    m = {r["id"]: float(r["p_tp"]) for r in rows}
    return np.array([m[r["id"]] for r in ghsa_rows])

p_base_path = DATA / "ghsa-eval" / "d1_predictions.jsonl"
p_targeted = load_p(AUDIT / "d1_targeted_identity_ghsa.jsonl")
p_lora = load_p(AUDIT / "d1_lora_identity_ghsa.jsonl")

if p_base_path.exists():
    p_base = load_p(p_base_path)

    print("=== Testing Ensemble Combinations ===")
    for alpha in [0.0, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 1.0]:

        blend = alpha * p_targeted + (1 - alpha) * p_base
        l0_auc = S.auc(defs["L0"], blend)
        l0_w = B.weighted_within_rule(defs["L0"], blend, rules)
        l2_auc = S.auc(defs["L2"], blend)
        l2_w = B.weighted_within_rule(defs["L2"], blend, rules)
        print(f"Alpha {alpha:.1f} (Targeted + Base) | L0 AUC: {l0_auc:.4f} | L0 W-AUC: {l0_w:.4f} | L2 AUC: {l2_auc:.4f} | L2 W-AUC: {l2_w:.4f}")

print("\n=== Testing LoRA + Targeted Blend ===")
for beta in [0.0, 0.3, 0.5, 0.7, 1.0]:
    blend = beta * p_lora + (1 - beta) * p_targeted
    l0_auc = S.auc(defs["L0"], blend)
    l0_w = B.weighted_within_rule(defs["L0"], blend, rules)
    l2_auc = S.auc(defs["L2"], blend)
    l2_w = B.weighted_within_rule(defs["L2"], blend, rules)
    l3_w = B.weighted_within_rule(defs["L3"], blend, rules)
    print(f"Beta {beta:.1f} (LoRA + Targeted) | L0 AUC: {l0_auc:.4f} | L0 W-AUC: {l0_w:.4f} | L2 AUC: {l2_auc:.4f} | L2 W-AUC: {l2_w:.4f} | L3 W-AUC: {l3_w:.4f}")
