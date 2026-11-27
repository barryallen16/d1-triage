"""LiquidAI d1-3B Alert Triage Engine."""
import os
import sys
import time
from dataclasses import dataclass

from d1_triage.sink_finder import build_annotated_prompt, find_sink_line

MODEL_NAME = "LiquidAI/d1-3B"

TRIAGE_QUESTION = (
    "Is this static-analysis warning a real, exploitable security bug at the flagged sink (marked with >>>) in the code below? "
    "Answer yes only if untrusted input reaches this specific sink without an effective guard."
)

TRIAGE_CRITERIA = {
    "true": "Untrusted input reaches the flagged sink marked with '>>>', and no effective validation, escaping, or containment check neutralizes it in the code.",
    "false": "The flagged sink is protected by guards/validation, input is from a trusted or static source, or the pattern is safe or style-only.",
}

QUESTIONS = {
    "tp": {
        "type": "noul",
        "instructions": TRIAGE_QUESTION,
        "criteria": TRIAGE_CRITERIA,
    }
}


@dataclass
class TriageFinding:
    id: str
    rule: str
    cwe: str
    file_path: str
    line_number: int
    code_window: str
    message: str = ""
    ground_truth: str | None = None


@dataclass
class TriageResult:
    finding_id: str
    rule: str
    cwe: str
    file_path: str
    line_number: int
    decision: str
    is_exploitable: bool
    p_tp: float
    confidence_pct: float
    sink_statement: str
    latency_ms: float
    device: str
    explanation: str = ""
    ground_truth: str | None = None


def generate_explanation(finding: TriageFinding, is_exploitable: bool, sink_stmt: str) -> str:
    """Deterministic CWE-level remediation hint or safe-pattern description."""
    rule_lower = finding.rule.lower()
    cwe_lower = finding.cwe.lower()

    if "path-traversal" in rule_lower or "cwe-22" in cwe_lower:
        if is_exploitable:
            return f"Untrusted input reaches filesystem sink ('{sink_stmt}') without verifying canonical path containment (getCanonicalPath().startsWith(baseDir))."
        return f"Path sink ('{sink_stmt}') is protected by directory containment or resolves against a sanitized path."

    if "documentbuilder" in rule_lower or "xxe" in rule_lower or "cwe-611" in cwe_lower:
        if is_exploitable:
            return f"XML parser initialized at '{sink_stmt}' without enabling FEATURE_SECURE_PROCESSING or disallowing external DTDs."
        return f"XML parser at '{sink_stmt}' explicitly enforces secure processing features, neutralizing external entity expansion."

    if "sql" in rule_lower or "cwe-89" in cwe_lower:
        if is_exploitable:
            return f"Dynamic SQL query constructed at '{sink_stmt}' without parameterized PreparedStatement binding."
        return f"SQL query at '{sink_stmt}' uses parameterized positional placeholders or fixed constant statements."

    if "deserialization" in rule_lower or "cwe-502" in cwe_lower:
        if is_exploitable:
            return f"Untrusted stream decoded at '{sink_stmt}' without ClassFilter gadget inspection."
        return f"Deserialization at '{sink_stmt}' is guarded by class whitelisting or operates on trusted input."

    if "socket" in rule_lower or "unencrypted" in rule_lower:
        if is_exploitable:
            return f"Plaintext network socket created at '{sink_stmt}' without TLS encryption (SSLSocket)."
        return f"Network socket at '{sink_stmt}' operates on localhost loopback or is wrapped in TLS."


    if is_exploitable:
        return f"Exploitable security sink detected at line {finding.line_number} ('{sink_stmt}') without neutralizing guards."
    return f"Safe pattern: flagged sink at line {finding.line_number} is neutralized by defensive validation or static context."


def evaluate_ast_heuristics(code_window: str, rule: str, cwe: str) -> float:
    """Evaluate taint and sanitization heuristics on Java source when model weights are not loaded."""
    code_lower = code_window.lower()
    rule_lower = rule.lower()
    cwe_lower = cwe.lower()


    if "path" in rule_lower or "cwe-22" in cwe_lower:
        if any(g in code_window for g in ["getCanonicalPath().startsWith", "toRealPath", "normalize()", "startsWith(base"]):
            return 0.032
        return 0.968


    if "xml" in rule_lower or "xxe" in rule_lower or "documentbuilder" in rule_lower or "cwe-611" in cwe_lower:
        if any(g in code_window for g in ["FEATURE_SECURE_PROCESSING", "disallow-doctype-decl", "load-external-dtd"]):
            return 0.028
        return 0.975


    if "sql" in rule_lower or "cwe-89" in cwe_lower:
        if "preparedstatement" in code_lower and "?" in code_window and any(s in code_window for s in ["setString", "setInt", "setLong"]):
            return 0.021
        if "+" in code_window and any(q in code_lower for q in ["select", "insert", "update", "delete", "createquery"]):
            return 0.982
        return 0.045 if "?" in code_window else 0.950


    if "exec" in rule_lower or "command" in rule_lower or "cwe-78" in cwe_lower:
        if any(g in code_window for g in ["ProcessBuilder", "String[]"]) and "+" not in code_window:
            return 0.040
        return 0.985


    if "deserial" in rule_lower or "cwe-502" in cwe_lower:
        if any(g in code_window for g in ["ClassFilter", "setObjectInputFilter", "ValidatingObjectInputStream"]):
            return 0.035
        return 0.970


    if any(g in code_lower for g in ["validate", "whitelist", "sanitize", "check", "guard"]):
        return 0.250
    return 0.880


class D1TriageEngine:
    def __init__(self, model_name: str = MODEL_NAME, device: str | None = None, mock: bool = True, explain: bool = True):
        self.model_name = model_name
        self.mock = mock
        self.explain = explain
        self._device = device or "cpu"

    @property
    def device(self) -> str:
        return self._device

    def triage_one(self, finding: TriageFinding, threshold: float = 0.5) -> TriageResult:
        """Triage a single finding with statement-level sink grounding."""
        _sink_idx, sink_stmt = find_sink_line(finding.code_window, finding.rule)

        if not self.mock:
            raise RuntimeError(
                f"Live inference for {self.model_name} is not wired in this Space app. "
                "Pass --mock (mock=True) to run the AST heuristic baseline."
            )

        t0 = time.perf_counter()
        p_tp = evaluate_ast_heuristics(finding.code_window, finding.rule, finding.cwe)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        is_tp = p_tp >= threshold
        decision = "TRUE POSITIVE" if is_tp else "FALSE POSITIVE"
        conf = max(p_tp, 1.0 - p_tp) * 100.0

        explanation = generate_explanation(finding, is_tp, sink_stmt) if self.explain else ""

        return TriageResult(
            finding_id=finding.id,
            rule=finding.rule,
            cwe=finding.cwe,
            file_path=finding.file_path,
            line_number=finding.line_number,
            decision=decision,
            is_exploitable=is_tp,
            p_tp=round(p_tp, 4),
            confidence_pct=round(conf, 1),
            sink_statement=sink_stmt,
            latency_ms=round(elapsed_ms, 1),
            device=self.device,
            explanation=explanation,
            ground_truth=finding.ground_truth,
        )

    def triage_batch(self, findings: list[TriageFinding], threshold: float = 0.5) -> list[TriageResult]:
        """Triage a batch of findings."""
        return [self.triage_one(f, threshold=threshold) for f in findings]
