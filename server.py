from http.server import BaseHTTPRequestHandler, HTTPServer
import json, time, hashlib
from .config import HOST, PORT, SHARED_SECRET, NONCE_TTL_SECONDS, MAX_BODY_BYTES
from .security import make_signature, signature_matches, timestamp_is_fresh
from .auditlog import write_event
_seen = {}

class Handler(BaseHTTPRequestHandler):
    server_version = "LocalRequestLab/1.0"
    def log_message(self, *_): pass
    def reply(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path == "/health": self.reply(200, {"status":"ok", "scope":"local mock only"})
        else: self.reply(404, {"error":"not_found"})
    def do_POST(self):
        if self.path != "/v1/echo": return self.reply(404, {"error":"not_found"})
        try: length = int(self.headers.get("Content-Length", "0"))
        except ValueError: length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            write_event({"event":"request_rejected","reason":"invalid_content_length","status":413})
            return self.reply(413, {"error":"invalid_content_length"})
        raw = self.rfile.read(length)
        ts, nonce, supplied = (self.headers.get(h, "") for h in ("X-Lab-Timestamp","X-Lab-Nonce","X-Lab-Signature"))
        now = int(time.time())
        if not timestamp_is_fresh(ts, now):
            write_event({"event":"request_rejected","reason":"stale_or_invalid_timestamp","status":401}, raw)
            return self.reply(401, {"error":"stale_or_invalid_timestamp"})
        if not nonce or len(nonce) > 128 or any(c.isspace() for c in nonce):
            write_event({"event":"request_rejected","reason":"invalid_nonce","status":400}, raw)
            return self.reply(400, {"error":"invalid_nonce"})
        for n, expiry in list(_seen.items()):
            if expiry < now: _seen.pop(n, None)
        if nonce in _seen:
            write_event({"event":"request_rejected","reason":"replay_detected","status":409}, raw)
            return self.reply(409, {"error":"replay_detected"})
        expected = make_signature(ts, nonce, raw, SHARED_SECRET)
        if not signature_matches(expected, supplied):
            write_event({"event":"request_rejected","reason":"signature_mismatch","status":401}, raw)
            return self.reply(401, {"error":"signature_mismatch"})
        _seen[nonce] = now + NONCE_TTL_SECONDS
        try: body = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            write_event({"event":"request_rejected","reason":"invalid_json","status":400}, raw)
            return self.reply(400, {"error":"invalid_json"})
        digest = hashlib.sha256(raw).hexdigest()
        write_event({"event":"request_accepted","status":200,"body_sha256":digest}, raw)
        self.reply(200, {"accepted":True,"echo":body,"body_sha256":digest})

def main():
    print(f"Local-only mock server at http://{HOST}:{PORT}; do not expose publicly.")
    HTTPServer((HOST, PORT), Handler).serve_forever()
if __name__ == "__main__": main()
