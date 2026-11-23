"""Vercel Python function: POST /api/analyze  {"log": "...", "format": "auto|linux|windows", "year": 2026}

Returns the JSON report plus the Markdown report. Nothing is stored: the log is analysed in memory
and dropped when the request ends.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authsentry import analyze_text, to_dict, to_markdown  # noqa: E402

MAX_BYTES = 1_000_000  # 1 MB of log text per request


def handle(body: bytes, content_type: str = "application/json"):
    """Pure request handler (status, payload) so it can be unit-tested without a server."""
    if len(body) > MAX_BYTES:
        return 413, {"error": f"Log too large: limit is {MAX_BYTES // 1_000_000} MB per request."}
    if "application/json" not in (content_type or ""):
        return 415, {"error": "Send JSON: {\"log\": \"...\"}"}
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 400, {"error": "Body is not valid JSON."}
    if not isinstance(payload, dict):
        return 400, {"error": "Body must be a JSON object."}
    log = payload.get("log", "")
    if not isinstance(log, str) or not log.strip():
        return 400, {"error": "Field 'log' is empty."}
    year = payload.get("year")
    if year is not None:
        try:
            year = int(year)
        except (TypeError, ValueError):
            return 400, {"error": "Field 'year' must be a number."}
        if not 1970 <= year <= 2100:
            return 400, {"error": "Field 'year' is out of range."}
    try:
        result = analyze_text(log, fmt=str(payload.get("format", "auto")), year=year)
    except (ValueError, json.JSONDecodeError) as exc:
        return 400, {"error": f"Could not parse the log: {exc}"}
    out = to_dict(result)
    out["markdown"] = to_markdown(result)
    return 200, out


class handler(BaseHTTPRequestHandler):
    def _send(self, status, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        if length > MAX_BYTES:
            return self._send(413, {"error": f"Log too large: limit is {MAX_BYTES // 1_000_000} MB per request."})
        status, obj = handle(self.rfile.read(length), self.headers.get("content-type", ""))
        self._send(status, obj)

    def do_GET(self):
        self._send(200, {"service": "authsentry", "usage": "POST JSON {log, format?, year?} to this URL"})
