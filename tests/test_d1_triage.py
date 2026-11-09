"""Unit tests for Liquid AI d1-triage engine, sink finder, and CLI."""
import json
from pathlib import Path
from d1_triage.engine import D1TriageEngine, TriageFinding
from d1_triage.sink_finder import build_annotated_prompt, find_sink_line


def test_sink_finder_identifies_path_traversal():
    code = """public void read(String path) {
    File f = new File(baseDir, path);
    FileInputStream fis = new FileInputStream(f);
}"""
    idx, stmt = find_sink_line(code, "java.lang.security.audit.path-traversal")
    assert "new File" in stmt
    assert idx == 1


def test_sink_finder_identifies_xml_parser():
    code = """public void parse(InputStream is) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
}"""
    idx, stmt = find_sink_line(code, "documentbuilderfactory")
    assert "DocumentBuilderFactory" in stmt
    assert idx == 1


def test_sink_finder_fallback_on_unknown_rule():
    code = """public void doSomething() {
    int x = 42;
    System.out.println(x);
}"""
    idx, stmt = find_sink_line(code, "unknown.rule.custom")
    assert idx >= 0
    assert len(stmt) > 0


def test_annotated_prompt_tags_sink_line():
    code = """public void read(String path) {
    File f = new File(baseDir, path);
}"""
    prompt = build_annotated_prompt(code, "path-traversal", "CWE-22", 15, "Server.java")
    assert "Rule: path-traversal" in prompt
    assert "CWE: CWE-22" in prompt
    assert ">>> [ALERT LINE 15]:" in prompt
    assert "File f = new File(baseDir, path);" in prompt


def test_engine_mock_triage_one():
    engine = D1TriageEngine(mock=True)
    assert engine.device == "cpu"

    finding = TriageFinding(
        id="TEST-01",
        rule="java.lang.security.audit.path-traversal",
        cwe="CWE-22",
        file_path="src/App.java",
        line_number=42,
        code_window="File f = new File(baseDir, userInput);",
    )
    result = engine.triage_one(finding)
    assert result.finding_id == "TEST-01"
    assert 0.0 <= result.p_tp <= 1.0
    assert result.decision in ("TRUE POSITIVE", "FALSE POSITIVE")
    assert result.sink_statement == "File f = new File(baseDir, userInput);"
    assert result.latency_ms >= 0.0


def test_engine_mock_triage_batch():
    engine = D1TriageEngine(mock=True)
    findings = [
        TriageFinding(
            id=f"TEST-{i}",
            rule="rule.test",
            cwe="CWE-79",
            file_path="Test.java",
            line_number=i,
            code_window=f"String data = input_{i};",
        )
        for i in range(3)
    ]
    results = engine.triage_batch(findings)
    assert len(results) == 3
    assert [r.finding_id for r in results] == ["TEST-0", "TEST-1", "TEST-2"]


def test_json_export(tmp_path):
    from d1_triage.formatters import save_json_report

    engine = D1TriageEngine(mock=True)
    finding = TriageFinding(
        id="EXPORT-01",
        rule="test.rule",
        cwe="CWE-89",
        file_path="Db.java",
        line_number=10,
        code_window="stmt.execute(query);",
    )
    results = [engine.triage_one(finding)]
    out_file = tmp_path / "report.json"
    save_json_report(results, str(out_file))

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["id"] == "EXPORT-01"
    assert "is_exploitable" in data[0]
