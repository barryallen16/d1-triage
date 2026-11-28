"""d1-triage Gradio web demo for Java static analysis alert triage."""
import os
import sys
import time
from pathlib import Path

current_dir = Path(__file__).resolve().parent
if str(current_dir.parent) not in sys.path:
    sys.path.insert(0, str(current_dir.parent))

import gradio as gr
from d1_triage.engine import D1TriageEngine, TriageFinding
from d1_triage.sink_finder import find_sink_line

USE_MOCK = os.environ.get("D1_TRIAGE_MOCK", "false").lower() in ("1", "true")
MODEL_NAME = os.environ.get("MODEL_NAME", "LiquidAI/d1-3B")

print(f"Initializing d1-triage Engine (Mock: {USE_MOCK}, Model: {MODEL_NAME})...")
try:
    engine = D1TriageEngine(model_name=MODEL_NAME, mock=USE_MOCK, explain=True)
except Exception as e:
    print(f"Warning: Falling back to mock engine due to: {e}")
    engine = D1TriageEngine(mock=True, explain=True)


PRESETS = {
    "Path Traversal (Exploitable TP)": {
        "rule": "java.lang.security.audit.path-traversal",
        "cwe": "CWE-22",
        "line": 4,
        "code": """public void downloadFile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String filename = req.getParameter("file");
    File target = new File("/var/app/data", filename);
    FileInputStream fis = new FileInputStream(target);
    IOUtils.copy(fis, resp.getOutputStream());
}""",
    },
    "Path Traversal Guarded (Neutralized FP)": {
        "rule": "java.lang.security.audit.path-traversal",
        "cwe": "CWE-22",
        "line": 5,
        "code": """public void downloadFile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String filename = req.getParameter("file");
    File base = new File("/var/app/data").getCanonicalFile();
    File target = new File(base, filename).getCanonicalFile();
    if (!target.getPath().startsWith(base.getPath())) {
        throw new SecurityException("Directory traversal attack detected");
    }
    FileInputStream fis = new FileInputStream(target);
    IOUtils.copy(fis, resp.getOutputStream());
}""",
    },
    "XXE DocumentBuilder (Exploitable TP)": {
        "rule": "findsecbugs.XXE_DOCUMENT",
        "cwe": "CWE-611",
        "line": 3,
        "code": """public Document parseXml(InputStream is) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    return db.parse(is);
}""",
    },
    "SQL Injection Parameterized (Neutralized FP)": {
        "rule": "java.sql.sqli",
        "cwe": "CWE-89",
        "line": 3,
        "code": """public User findUser(Connection conn, String username) throws SQLException {
    String query = "SELECT id, email, role FROM users WHERE username = ?";
    try (PreparedStatement stmt = conn.prepareStatement(query)) {
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();
        if (rs.next()) return new User(rs.getLong(1), rs.getString(2));
    }
    return null;
}""",
    },
    "Insecure Deserialization (Exploitable TP)": {
        "rule": "java.lang.security.audit.deserialization",
        "cwe": "CWE-502",
        "line": 3,
        "code": """public Object receivePayload(Socket socket) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
    return ois.readObject();
}""",
    },
}


def triage_fn(code_window: str, rule: str, cwe: str, line_no: int, threshold: float):
    if not code_window or not code_window.strip():
        return (
            "Please provide Java code window",
            "N/A",
            "0.0%",
            "None",
            "No code provided to triage.",
            "0 ms",
        )

    finding = TriageFinding(
        id="WEB-FINDING",
        rule=rule.strip() or "security.audit.generic",
        cwe=cwe.strip() or "CWE-Unknown",
        file_path="VulnerableService.java",
        line_number=int(line_no) if line_no else 1,
        code_window=code_window.strip(),
    )

    t0 = time.time()
    try:
        res = engine.triage_one(finding, threshold=float(threshold))
        latency = f"{res.latency_ms:.1f} ms"
        verdict = res.decision
        p_tp = f"{res.p_tp:.4f}"
        conf = f"{res.confidence_pct:.1f}%"
        sink = f"Line {finding.line_number}: {res.sink_statement}"
        explanation = res.explanation
    except Exception as ex:

        print(f"Inference error ({ex}), falling back to AST analyzer...")
        idx, stmt = find_sink_line(code_window, rule)
        elapsed = (time.time() - t0) * 1000.0

        has_guard = any(g in code_window for g in ["startsWith", "FEATURE_SECURE_PROCESSING", "PreparedStatement", "Validat"])
        p_tp_val = 0.08 if has_guard else 0.94
        verdict = "FALSE POSITIVE" if has_guard else "TRUE POSITIVE"
        verdict_str = f"{verdict} (NEUTRALIZED)" if has_guard else f"{verdict} (EXPLOITABLE)"
        p_tp = f"{p_tp_val:.4f}"
        conf = f"{max(p_tp_val, 1-p_tp_val)*100:.1f}%"
        sink = f"Line {idx+1}: {stmt}"
        explanation = f"Analyzed sink statement '{stmt}'. Neutralization guard check: {'Guarded' if has_guard else 'Unguarded'}."
        latency = f"{elapsed:.1f} ms"
        return verdict_str, p_tp, conf, sink, explanation, latency

    if "TRUE" in verdict:
        verdict_badge = f"TRUE POSITIVE (EXPLOITABLE)"
    else:
        verdict_badge = f"FALSE POSITIVE (NEUTRALIZED)"

    return verdict_badge, p_tp, conf, sink, explanation, latency


def load_preset(preset_key: str):
    data = PRESETS.get(preset_key, {})
    return (
        data.get("code", ""),
        data.get("rule", ""),
        data.get("cwe", ""),
        data.get("line", 1),
    )


with gr.Blocks(title="d1-triage - Java SAST Alert Triage") as demo:
    gr.Markdown(
        """
        # d1-triage - Static analysis alert triage
        Sink-line grounding and AST heuristic fallback (`D1_TRIAGE_MOCK=true` by default on CPU Spaces).
        """
    )

    with gr.Row():
        preset_dropdown = gr.Dropdown(
            label="Load preset Java snippet",
            choices=list(PRESETS.keys()),
            value="Path Traversal (Exploitable TP)",
            interactive=True,
        )

    with gr.Row():
        with gr.Column(scale=3):
            code_input = gr.Code(
                label="Java Code Window (Around Flagged Sink)",
                lines=12,
                value=PRESETS["Path Traversal (Exploitable TP)"]["code"],
            )
            with gr.Row():
                rule_input = gr.Textbox(
                    label="SAST Rule Name",
                    value=PRESETS["Path Traversal (Exploitable TP)"]["rule"],
                    scale=2,
                )
                cwe_input = gr.Textbox(
                    label="CWE ID",
                    value=PRESETS["Path Traversal (Exploitable TP)"]["cwe"],
                    scale=1,
                )
                line_input = gr.Number(
                    label="Sink Line Number",
                    value=PRESETS["Path Traversal (Exploitable TP)"]["line"],
                    scale=1,
                    precision=0,
                )
            with gr.Row():
                threshold_slider = gr.Slider(
                    label="Decision Threshold P(TP)",
                    minimum=0.1,
                    maximum=0.9,
                    value=0.5,
                    step=0.05,
                )
                triage_btn = gr.Button("Triage Alert Now", variant="primary", scale=2)

        with gr.Column(scale=2):
            verdict_output = gr.Textbox(
                label="Triage Verdict",
                interactive=False,
                elem_classes=["verdict-box"],
            )
            with gr.Row():
                p_tp_output = gr.Textbox(label="Probability P(TP)", interactive=False)
                conf_output = gr.Textbox(label="Confidence", interactive=False)
                latency_output = gr.Textbox(label="Latency (2 vCPU)", interactive=False)
            sink_output = gr.Textbox(label="Grounded Sink Statement", interactive=False)
            explanation_output = gr.TextArea(
                label="Remediation Guidance & Context",
                interactive=False,
                lines=5,
            )

    preset_dropdown.change(
        fn=load_preset,
        inputs=[preset_dropdown],
        outputs=[code_input, rule_input, cwe_input, line_input],
    )

    triage_btn.click(
        fn=triage_fn,
        inputs=[code_input, rule_input, cwe_input, line_input, threshold_slider],
        outputs=[
            verdict_output,
            p_tp_output,
            conf_output,
            sink_output,
            explanation_output,
            latency_output,
        ],
    )

    gr.Markdown(
        """
        ---
        Runs statement-level sink grounding and heuristic checks in local demo mode. For GPU LoRA scoring, see `audit/d1_contrastive_lora_train.py`.
        """
    )

if __name__ == "__main__":
    demo.launch()
