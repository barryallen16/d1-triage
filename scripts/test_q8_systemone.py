"""Test exact LiquidAI d1-3B System 1 prompt on local Q8_0 weights."""
import math
import llama_cpp
from d1_triage.cli import DEMO_FINDINGS
from d1_triage.sink_finder import build_annotated_prompt
from d1_triage.engine import TRIAGE_QUESTION, TRIAGE_CRITERIA

print("Loading Q8_0 GGUF model...")
llm = llama_cpp.Llama(
    model_path="models/d1-3B-Q8_0.gguf",
    n_ctx=2048,
    n_threads=4,
    logits_all=True,
    verbose=False,
)

yes_forms = ["yes", "Yes", "YES", " yes", " Yes"]
no_forms = ["no", "No", "NO", " no", " No"]
yes_ids = list(set(llm.tokenize(w.encode("utf-8"))[-1] for w in yes_forms))
no_ids = list(set(llm.tokenize(w.encode("utf-8"))[-1] for w in no_forms))

print(f"Yes token IDs: {yes_ids}")
print(f"No token IDs: {no_ids}")

for f in DEMO_FINDINGS:
    state = build_annotated_prompt(
        f.code_window, f.rule, f.cwe, f.line_number, f.file_path, f.message
    )
    prompt = (
        f"<|im_start|>user\n"
        f"{state}\n\n"
        f"QUESTION:\n"
        f"{TRIAGE_QUESTION}\n"
        f"Yes: {TRIAGE_CRITERIA['true']}\n"
        f"No: {TRIAGE_CRITERIA['false']}\n\n"
        f"Reply with yes or no only.<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )

    tokens = llm.tokenize(prompt.encode("utf-8"))
    llm.reset()
    llm.eval(tokens)
    logits = llm.eval_logits[-1]

    score_yes = max(float(logits[i]) for i in yes_ids)
    score_no = max(float(logits[i]) for i in no_ids)
    m = max(score_yes, score_no)
    e_yes = math.exp(score_yes - m)
    e_no = math.exp(score_no - m)
    p_tp = e_yes / (e_yes + e_no)

    verdict = "TRUE POSITIVE (EXPLOITABLE)" if p_tp >= 0.5 else "FALSE POSITIVE (GUARDED)"
    print(f"\n{f.id}:")
    print(f"  P(TP) = {p_tp:.4f} ({p_tp*100:.1f}%)")
    print(f"  Verdict: {verdict}")
    print(f"  Ground Truth: {f.ground_truth}")
