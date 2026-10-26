import hashlib, hmac, json, re, time
from .config import SHARED_SECRET, TIMESTAMP_TOLERANCE_SECONDS

SENSITIVE = re.compile(r"(authorization|cookie|session|token|password|secret|device_id|openudid|sec_device_id|ms_token|x-argus|x-gorgon|x-ladon|x-perseus|signature)", re.I)

def body_sha256(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical_message(timestamp, nonce, raw_body):
    return f"{timestamp}\n{nonce}\n{body_sha256(raw_body)}".encode()

def make_signature(timestamp, nonce, raw_body, secret=SHARED_SECRET):
    return hmac.new(secret.encode(), canonical_message(timestamp, nonce, raw_body), hashlib.sha256).hexdigest()

def signature_matches(expected, supplied):
    return hmac.compare_digest(expected, supplied)

def timestamp_is_fresh(timestamp, now=None):
    try: parsed = int(timestamp)
    except (TypeError, ValueError): return False
    current = int(time.time() if now is None else now)
    return abs(current - parsed) <= TIMESTAMP_TOLERANCE_SECONDS

def redact(value, key=""):
    if SENSITIVE.search(key): return "[REDACTED]"
    if isinstance(value, dict): return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list): return [redact(v, key) for v in value]
    if isinstance(value, str) and len(value) > 256: return value[:48] + "...[TRUNCATED]"
    return value

def safe_json_preview(raw):
    try: return redact(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"body_bytes": len(raw), "body_sha256": body_sha256(raw)}
