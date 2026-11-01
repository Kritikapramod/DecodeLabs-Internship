"""HTTP server (standard library only). Serves the frontend and POST /api/analyze."""
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from phishing_analyzer import analyze, InputError

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8"), "/script.js": ("script.js", "application/javascript; charset=utf-8")}
MAX_BODY = 64 * 1024  # bytes; anything larger is rejected before reading


class Handler(BaseHTTPRequestHandler):
    timeout = 10  # seconds; a client that stalls mid-request cannot hold a thread forever
    _head = False

    def send_error(self, code, message=None, explain=None):  # always JSON, never HTML
        self._send(code, {"error": message or "Request error."})

    def _not_allowed(self):
        self._send(405, {"error": "Method not allowed."}, extra={"Allow": "GET, HEAD, POST"})

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_allowed

    def do_HEAD(self):
        self._head = True
        self.do_GET()

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not self._head:
            self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/health":
            return self._send(200, {"status": "ok"})
        if path in STATIC:  # whitelist only: no arbitrary file access
            name, ctype = STATIC[path]
            try:
                with open(os.path.join(BASE, name), "rb") as f:
                    return self._send(200, f.read(), ctype)
            except OSError:
                return self._send(404, {"error": "Not found."})
        if path == "/api/analyze":
            return self._not_allowed()
        self._send(404, {"error": "Not found."})

    def do_POST(self):
        if self.path.split("?")[0] != "/api/analyze":
            return self._send(404, {"error": "Not found."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "Invalid Content-Length."})
        if length <= 0:
            return self._send(400, {"error": "Request body is empty."})
        if length > MAX_BODY:
            return self._send(413, {"error": "Request too large."})
        try:
            raw = self.rfile.read(length)
        except OSError:  # includes read timeout
            return self._send(408, {"error": "Request timed out."})
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._send(400, {"error": "Invalid JSON."})
        if not isinstance(payload, dict):
            return self._send(400, {"error": "JSON body must be an object with a 'message' field."})
        try:
            self._send(200, analyze(payload.get("message")))
        except InputError as e:
            self._send(e.status, {"error": str(e)})
        except Exception as e:  # details go to the server log only, never to the user
            print("Internal error:", repr(e), file=sys.stderr)
            self._send(500, {"error": "Internal error. Please try again."})


def make_server(port=8000):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print("PhishGuard running at http://127.0.0.1:%d  (Ctrl+C to stop)" % port)
    try:
        make_server(port).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
