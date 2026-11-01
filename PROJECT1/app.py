"""Local server: serves the page and exposes POST /api/check. Standard library only."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from password_checker import evaluate_password

HOST, PORT = "127.0.0.1", 8000          # localhost only: not reachable from other machines
STATIC = Path(__file__).resolve().parent  # frontend files sit next to app.py (no static/ folder)
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/style.css": ("style.css", "text/css; charset=utf-8"),
         "/script.js": ("script.js", "application/javascript; charset=utf-8")}
MAX_BODY = 2048


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, data):
        self._send(status, json.dumps(data).encode(), "application/json")

    def do_GET(self):
        entry = FILES.get(self.path)          # whitelist: no arbitrary file access
        if not entry:
            return self._json(404, {"error": "Not found"})
        name, ctype = entry
        self._send(200, (STATIC / name).read_bytes(), ctype)

    def do_POST(self):
        if self.path != "/api/check":
            return self._json(404, {"error": "Not found"})
        try:
            size = int(self.headers.get("Content-Length", 0))
            if size > MAX_BODY:
                return self._json(413, {"error": "Request too large"})
            data = json.loads(self.rfile.read(size))
            password = data["password"]       # used exactly as received (no strip)
            self._json(200, evaluate_password(password))
        except (ValueError, KeyError, TypeError) as exc:
            self._json(400, {"error": "Invalid request: " + type(exc).__name__})

    def log_message(self, *args):
        pass  # disable request logging so nothing about inputs is ever printed


if __name__ == "__main__":
    print(f"Password Strength Checker running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    HTTPServer((HOST, PORT), Handler).serve_forever()
