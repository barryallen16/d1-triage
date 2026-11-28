"""Generate self-contained Kaggle training scripts from full_method_train.jsonl."""
import base64
import gzip
from pathlib import Path

AUDIT = Path(__file__).resolve().parent
ROOT = AUDIT.parent

train_b64 = base64.b64encode(gzip.compress((AUDIT / "full_method_train.jsonl").read_bytes(), compresslevel=9)).decode()
sink_b64 = base64.b64encode(gzip.compress((ROOT / "d1_triage" / "sink_finder.py").read_bytes(), compresslevel=9)).decode()

TEMPLATE = '''"""Kaggle GPU run: {name}."""
import base64
import gc
import gzip
import json
import os
import random
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

SCRATCH = Path("/kaggle/tmp") if Path("/kaggle/tmp").exists() else Path(".")
SCRATCH.mkdir(parents=True, exist_ok=True)
os.environ["HF_HOME"] = str(SCRATCH / "hf_cache")
os.environ["WANDB_DISABLED"] = "true"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

# Remove broken preinstalled torchao before importing transformers/peft
subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "torchao"], check=False)

TRAIN_B64 = """{train_b64}"""
SINK_B64 = """{sink_b64}"""

(SCRATCH / "full_method_train.jsonl").write_bytes(gzip.decompress(base64.b64decode(TRAIN_B64)))
(SCRATCH / "sink_finder.py").write_bytes(gzip.decompress(base64.b64decode(SINK_B64)))
sys.path.insert(0, str(SCRATCH))

from sink_finder import build_annotated_prompt, find_sink_line

import numpy as np
import torch
import torch.nn.functional as F
from datasets import Dataset
from huggingface_hub import snapshot_download
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForImageTextToText, AutoTokenizer, Trainer, TrainingArguments

KL_WEIGHT = {kl_weight}
LORA_R = {lora_r}
LORA_ALPHA = {lora_alpha}
EPOCHS = {epochs}
LR = {lr}
SEMGREP_UPWEIGHT = {semgrep_upweight}
MAX_SEQ = 1536
MODEL = "LiquidAI/d1-3B"

QUESTION = (
    "Is this static-analysis warning a real, exploitable security bug at the flagged sink (marked with >>>) in the code below? "
    "Answer yes only if untrusted input reaches this specific sink without an effective guard."
)
CRITERIA = {{
    "true": "Untrusted input reaches the flagged sink marked with '>>>', and no effective validation, escaping, or containment check neutralizes it in the code.",
    "false": "The flagged sink is protected by guards/validation, input is from a trusted or static source, or the pattern is safe or style-only.",
}}
QUESTIONS = {{"tp": {{"type": "noul", "instructions": QUESTION, "criteria": CRITERIA}}}}

CWE_TO_SEMGREP_RULE = {{
    "CWE-22": "java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
    "CWE-74": "java.lang.security.audit.el-injection.el-injection",
    "CWE-77": "java.lang.security.audit.command-injection.command-injection",
    "CWE-78": "java.lang.security.audit.command-injection.command-injection",
    "CWE-79": "java.lang.security.audit.xss.no-direct-response-writer.no-direct-response-writer",
    "CWE-89": "java.lang.security.audit.formatted-sql-string.formatted-sql-string",
    "CWE-94": "java.lang.security.audit.script-engine-injection.script-engine-injection",
    "CWE-502": "java.lang.security.audit.object-deserialization.object-deserialization",
    "CWE-611": "java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing",
    "CWE-918": "java.lang.security.audit.ssrf.ssrf",
}}

def state_of_annotated(row, window_override=None):
    window = (window_override if window_override is not None else row.get("code_window", ""))[:8000]
    rule = row["rule"]
    if rule.endswith(".vulnerability"):
        rule = CWE_TO_SEMGREP_RULE.get(row.get("cwe", ""), rule)
    line_no = row.get("line", 0)
    if not line_no:
        sink_idx, _ = find_sink_line(window, rule)
        line_no = sink_idx + 1
    return build_annotated_prompt(
        code_window=window, rule=rule, cwe=row["cwe"],
        line_no=line_no, file_path=str(row["file"]), message=row.get("message", ""),
    )

def build_rule_swap(rows, seed=3407):
    rng = random.Random(seed)
    by_rule = {{}}
    for i, r in enumerate(rows):
        by_rule.setdefault(r["rule"], []).append(i)
    swapped = [None] * len(rows)
    for rule, indices in by_rule.items():
        if len(indices) == 1:
            swapped[indices[0]] = rows[indices[0]]["code_window"]
        else:
            shuffled = list(indices)
            for _ in range(100):
                rng.shuffle(shuffled)
                if all(a != b for a, b in zip(indices, shuffled)):
                    break
            for orig, new in zip(indices, shuffled):
                swapped[orig] = rows[new]["code_window"]
    return swapped

def score_rows(model, tokenizer, q, render_fn, readout_fn, rows, window_overrides=None):
    out = []
    model.eval()
    model.config.use_cache = True
    for i, row in enumerate(rows):
        w_ov = window_overrides[i] if window_overrides else None
        prompt = render_fn(tokenizer=tokenizer, state=state_of_annotated(row, w_ov), q=q, bos=tokenizer.bos_token)
        inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=False)
        inputs = {{k: v.to("cuda") for k, v in inputs.items()}}
        t0 = time.time()
        with torch.inference_mode():
            row_logits = model(**inputs, logits_to_keep=1).logits[0, -1].float()
            logz = row_logits - torch.logsumexp(row_logits, dim=-1)
            p_tp = float(readout_fn(tokenizer, q, logz)[0])
        elapsed = time.time() - t0
        out.append({{
            "id": row["id"], "label": row["label"], "p_tp": p_tp,
            "confidence": round(max(p_tp, 1.0 - p_tp), 6), "seconds": round(elapsed, 3),
        }})
    return out

def rank_auc(y, scores):
    scores = np.asarray(scores, float)
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), float)
    ss = scores[order]
    i = 0
    while i < len(scores):
        j = i
        while j + 1 < len(scores) and ss[j + 1] == ss[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    pos = y == 1
    return float((ranks[pos].sum() - pos.sum() * (pos.sum() + 1) / 2.0) / (pos.sum() * (~pos).sum()))

def main():
    if torch.cuda.device_count() == 0:
        sys.exit(1)
    print(f"=== Starting Kaggle run: {name} | GPU: {{torch.cuda.get_device_name(0)}} ===", flush=True)
    local_dir = snapshot_download(MODEL)
    sys.path.insert(0, local_dir)
    from prompt import as_question, readout, readout_ids, render

    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    q = as_question(QUESTIONS["tp"])
    yes_ids, no_ids = readout_ids(tokenizer, q)

    all_rows = [json.loads(l) for l in open(SCRATCH / "full_method_train.jsonl", encoding="utf-8") if l.strip()]
    train_rows = [r for r in all_rows if "/test/" not in r["file"].lower() and "test.java" not in r["file"].lower()]
    if SEMGREP_UPWEIGHT > 1:
        sg_rows = [r for r in train_rows if str(r.get("source", "")).startswith("semgrep")]
        train_rows = train_rows + sg_rows * (SEMGREP_UPWEIGHT - 1)
    random.Random(3407).shuffle(train_rows)
    print(f"Loaded {{len(train_rows)}} training rows (yes_ids={{yes_ids}}, no_ids={{no_ids}})", flush=True)

    def fmt(row):
        prompt = render(tokenizer=tokenizer, state=state_of_annotated(row), q=q, bos=tokenizer.bos_token)
        p_ids = tokenizer(prompt, add_special_tokens=False).input_ids
        if len(p_ids) > MAX_SEQ:
            p_ids = p_ids[-MAX_SEQ:]
        cls_label = 0 if row["label"] == "TP" else 1
        return {{"input_ids": p_ids, "attention_mask": [1] * len(p_ids), "cls_label": cls_label}}

    dataset = Dataset.from_list([fmt(r) for r in train_rows])

    base_model = AutoModelForImageTextToText.from_pretrained(
        MODEL, torch_dtype=torch.float16, device_map={{"": 0}}, trust_remote_code=True,
    )
    base_model.config.use_cache = False
    base_model.gradient_checkpointing_enable()

    lora_config = LoraConfig(
        r=LORA_R, lora_alpha=LORA_ALPHA,
        target_modules=r".*language_model.*\\.(q_proj|k_proj|v_proj|out_proj)",
        lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
    )
    peft_model = get_peft_model(base_model, lora_config)
    peft_model.print_trainable_parameters()

    class LogitReadoutTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            cls_label = inputs.pop("cls_label")
            with torch.no_grad():
                with model.disable_adapter():
                    base_logits = model(**inputs, logits_to_keep=1).logits[:, -1, :].float()
                    base_pair = torch.stack([
                        torch.logsumexp(base_logits[:, yes_ids], dim=-1),
                        torch.logsumexp(base_logits[:, no_ids], dim=-1),
                    ], dim=-1)
                    base_probs = F.softmax(base_pair, dim=-1)

            outputs = model(**inputs, logits_to_keep=1)
            last_logits = outputs.logits[:, -1, :].float()
            yes_l = torch.logsumexp(last_logits[:, yes_ids], dim=-1)
            no_l = torch.logsumexp(last_logits[:, no_ids], dim=-1)
            pair = torch.stack([yes_l, no_l], dim=-1)
            ce_loss = F.cross_entropy(pair, cls_label.to(pair.device), label_smoothing=0.05)
            kl_loss = F.kl_div(F.log_softmax(pair, dim=-1), base_probs, reduction="batchmean")
            loss = (1.0 - KL_WEIGHT) * ce_loss + KL_WEIGHT * kl_loss
            return (loss, outputs) if return_outputs else loss

    trainer = LogitReadoutTrainer(
        model=peft_model,
        train_dataset=dataset,
        args=TrainingArguments(
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            warmup_steps=10,
            num_train_epochs=EPOCHS,
            learning_rate=LR,
            logging_steps=20,
            weight_decay=0.05,
            lr_scheduler_type="cosine",
            seed=3407,
            output_dir=str(SCRATCH / "checkpoints"),
            report_to="none",
            save_strategy="no",
            fp16=True,
            remove_unused_columns=False,
        ),
    )

    t_start = time.time()
    trainer.train()
    print(f"Training completed in {{time.time() - t_start:.1f}}s!", flush=True)

    merged_model = peft_model.merge_and_unload()
    del peft_model, trainer
    gc.collect()
    torch.cuda.empty_cache()

    ghsa_rows = [json.loads(l) for l in urllib.request.urlopen(
        "https://huggingface.co/datasets/barryallen16/d1-triage/resolve/main/ghsa-scan-labeled.jsonl"
    ).read().decode().splitlines() if l.strip()]
    vul4j_rows = [json.loads(l) for l in urllib.request.urlopen(
        "https://huggingface.co/datasets/barryallen16/d1-triage/resolve/main/vul4j-scan-labeled.jsonl"
    ).read().decode().splitlines() if l.strip()]

    print("Evaluating GHSA Identity...", flush=True)
    ghsa_id = score_rows(merged_model, tokenizer, q, render, readout, ghsa_rows)
    print("Evaluating GHSA Swap...", flush=True)
    swapped = build_rule_swap(ghsa_rows)
    ghsa_sw = score_rows(merged_model, tokenizer, q, render, readout, ghsa_rows, window_overrides=swapped)
    print("Evaluating Vul4J Identity...", flush=True)
    vul4j_id = score_rows(merged_model, tokenizer, q, render, readout, vul4j_rows)

    g_y = np.array([1 if r["label"] == "TP" else 0 for r in ghsa_rows])
    g_s = np.array([r["p_tp"] for r in ghsa_id])
    g_sw = np.array([r["p_tp"] for r in ghsa_sw])
    v_y = np.array([1 if r["label"] == "TP" else 0 for r in vul4j_rows])
    v_s = np.array([r["p_tp"] for r in vul4j_id])
    print(f"SUMMARY {name}: GHSA L0 AUC={{rank_auc(g_y, g_s):.4f}} | L0 Swap={{rank_auc(g_y, g_s) - rank_auc(g_y, g_sw):+.4f}} | Vul4J AUC={{rank_auc(v_y, v_s):.4f}}", flush=True)

    bundle = {{
        "ghsa_identity": ghsa_id,
        "ghsa_swap": ghsa_sw,
        "vul4j_identity": vul4j_id,
    }}
    raw = json.dumps(bundle).encode("utf-8")
    b64 = base64.b64encode(gzip.compress(raw, compresslevel=9)).decode("ascii")
    print("===BUNDLE_B64_START===", flush=True)
    for i in range(0, len(b64), 120):
        print(b64[i:i+120], flush=True)
    print("===BUNDLE_B64_END===", flush=True)

if __name__ == "__main__":
    main()
'''

configs = [
    {"file": "kaggle_raw_kl03.py", "name": "kl03-r8", "kl_weight": 0.3, "lora_r": 8, "lora_alpha": 16, "epochs": 1, "lr": 3e-5, "semgrep_upweight": 1},
    {"file": "kaggle_raw_kl05.py", "name": "kl05-r16", "kl_weight": 0.5, "lora_r": 16, "lora_alpha": 32, "epochs": 1, "lr": 3e-5, "semgrep_upweight": 1},
    {"file": "kaggle_raw_kl02_sg3.py", "name": "kl02-sg3-ep2", "kl_weight": 0.2, "lora_r": 8, "lora_alpha": 16, "epochs": 2, "lr": 3e-5, "semgrep_upweight": 3},
]

for cfg in configs:
    src = TEMPLATE.format(train_b64=train_b64, sink_b64=sink_b64, **cfg)
    out = AUDIT / cfg["file"]
    out.write_text(src, encoding="utf-8")
    print("Wrote", out.name, f"({len(src)//1024} KB)")
