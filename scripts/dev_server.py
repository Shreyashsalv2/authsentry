"""Run the demo locally: python scripts/dev_server.py  ->  http://127.0.0.1:8000

Serves the static page and routes POST /api/analyze to the same handler Vercel runs.
"""
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
import analyze  # noqa: E402


class Dev(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def do_POST(self):
        if self.path.split("?")[0] != "/api/analyze":
            return self.send_error(404)
        analyze.handler.do_POST(self)

    _send = analyze.handler._send


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"AuthSentry dev server on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Dev).serve_forever()
