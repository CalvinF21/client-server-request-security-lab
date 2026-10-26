import argparse, json, secrets, time, urllib.request, urllib.error
from .config import HOST, PORT, SHARED_SECRET
from .security import make_signature
BASE = f"http://{HOST}:{PORT}"

def send(payload, nonce=None, timestamp=None, tamper=False):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ts = str(int(time.time()) if timestamp is None else timestamp); nonce = nonce or secrets.token_hex(16)
    sig = make_signature(ts, nonce, raw, SHARED_SECRET)
    if tamper: raw += b" "
    req = urllib.request.Request(BASE+"/v1/echo", data=raw, method="POST", headers={
        "Content-Type":"application/json", "X-Lab-Timestamp":ts, "X-Lab-Nonce":nonce, "X-Lab-Signature":sig})
    try:
        with urllib.request.urlopen(req, timeout=3) as r: return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()

def main():
    p = argparse.ArgumentParser(); p.add_argument("--demo", action="store_true"); args = p.parse_args()
    if not args.demo:
        print(send({"case":"baseline","user":"synthetic-user","token":"DO-NOT-LOG-THIS"})); return
    payload = {"case":"tamper-demo","authorization":"fake-demo-secret","result":"synthetic"}
    nonce = secrets.token_hex(16)
    print("baseline:", send(payload, nonce=nonce))
    print("replay:", send(payload, nonce=nonce))
    print("body tamper:", send(payload, tamper=True))
    print("stale timestamp:", send(payload, timestamp=int(time.time())-10000))
if __name__ == "__main__": main()
