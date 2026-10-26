import json, os, threading
from datetime import datetime, timezone
from .config import LOG_PATH
from .security import safe_json_preview
_lock = threading.Lock()

def write_event(event, raw_body=b""):
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    record = {"time_utc": datetime.now(timezone.utc).isoformat(), **event,
              "body_preview": safe_json_preview(raw_body) if raw_body else None}
    with _lock, open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
