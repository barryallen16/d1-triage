"""Local HTTP Server and Live Triage API Bridge.

Serves the static site and provides a live JSON triage endpoint:
    POST /api/triage -> D1TriageEngine.triage_one()
"""
import argparse
import json
import os
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

from d1_triage.engine import D1TriageEngine, TriageFinding

SITE_DIR = Path(__file__).resolve().parent.parent / "site"
MODEL_NAME = "LiquidAI/d1-3B"

_engine = None
_lock = threading.Lock()


def get_engine():
    global _engine
    if _engine is None:
        use_mock = os.environ.get("D1_TRIAGE_MOCK", "false").lower() in ("1", "true")
        model = os.environ.get("MODEL_NAME", MODEL_NAME)
        _engine = D1TriageEngine(model_name=model, mock=use_mock, explain=True)
    return _engine


class TriageHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SITE_DIR), **kwargs)

    def end_headers(self):
        origin = self.headers.get("Origin", "")
        if origin.startswith(("http://localhost:", "http://127.0.0.1:", "http://localhost", "http://127.0.0.1")):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "model": MODEL_NAME}).encode("utf-8"))
            return
        super().do_GET()

    def do_POST(self):
        if self.path == "/api/triage":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON body"}')
                return

            code = data.get("code", "")
            rule = data.get("rule", "java.lang.security.audit.generic")
            cwe = data.get("cwe", "CWE-Unknown")
            line = int(data.get("line", 1))
            threshold = float(data.get("threshold", 0.5))

            finding = TriageFinding(
                id="PLAYGROUND-REQ",
                rule=rule,
                cwe=cwe,
                file_path="CustomSnippet.java",
                line_number=line,
                code_window=code,
            )

            try:
                engine = get_engine()
                with _lock:
                    res = engine.triage_one(finding, threshold=threshold)
                payload = {
                    "decision": res.decision,
                    "is_exploitable": res.is_exploitable,
                    "p_tp": res.p_tp,
                    "confidence_pct": res.confidence_pct,
                    "sink_statement": res.sink_statement,
                    "latency_ms": res.latency_ms,
                    "device": res.device,
                    "explanation": res.explanation,
                    "backend": "live-python",
                }
            except Exception as ex:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(ex)}).encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                self.wfile.write(json.dumps(payload).encode("utf-8"))
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            return

        self.send_response(404)
        self.end_headers()


def run_server(port: int = 8000, host: str = "127.0.0.1"):
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, TriageHTTPHandler)
    print(f"d1-triage server running at http://{host}:{port}/ (serving {SITE_DIR})")
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="d1-triage Site & API Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    args = parser.parse_args()
    run_server(port=args.port, host=args.host)
