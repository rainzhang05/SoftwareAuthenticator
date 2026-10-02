#!/usr/bin/env python3
"""Queue tests for a browser page in remote-control mode.

  q.py chrome R1 R3 L4                       presets, in order
  q.py chrome signin:-50:disc[:required]     sign in with each matching credential at the RP
  q.py chrome wait:5000                      pause
  q.py chrome abort:R1:8000                  run R1 and abort it from the page after 8 s
  q.py chrome --clear ...                    drop what is still queued first

The browser is "chrome" (any Chromium) or "firefox": a page polls the queue of
its own family. The presets are the ones index.html lists (R1-R25, L1-L7).
"""
import json
import os
import sys
import urllib.request

BASE = f"http://localhost:{os.environ.get('RP_PORT', '8080')}"
# The names of the algorithms, as in ALGORITHMS in tests/e2e/ctap.py.
NAMES = {-7: "ES256", -48: "ML-DSA-44", -49: "ML-DSA-65", -50: "ML-DSA-87", -9: "ESP256", -35: "ES384", -51: "ESP384", -36: "ES512", -52: "ESP512"}


def get(path):
    return json.loads(urllib.request.urlopen(BASE + path).read())


def post(path, body):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req).read())


def main(argv):
    browser, args = argv[0], argv[1:]
    clear = "--clear" in args
    args = [a for a in args if a != "--clear"]
    items = []
    db = get("/api/db")
    for a in args:
        if a.startswith("signin:"):
            parts = a.split(":")
            alg = int(parts[1])
            kind = parts[2] if len(parts) > 2 else "any"
            uv = parts[3] if len(parts) > 3 else "discouraged"
            for user, u in db["users"].items():
                for c in u["credentials"]:
                    if c["alg"] == alg and (kind == "any" or (kind == "disc") == bool(c["disc"])):
                        items.append({"kind": "login", "cfg": {
                            "username": user, "allow": "cred:" + c["id"], "userVerification": uv,
                            "label": f"sign in {user} {NAMES[alg]} {'disc' if c['disc'] else 'non-disc'} UV {uv} (made {c['created']})"}})
        elif a.startswith("wait:"):
            items.append({"wait_ms": int(a[5:])})
        elif a.startswith("abort:"):
            _, preset, ms = a.split(":")
            items.append({"preset": preset, "abort_after_ms": int(ms), "label": f"{preset} aborted by page after {ms} ms"})
        else:
            items.append({"preset": a})
    print(post("/api/enqueue", {"browser": browser, "items": items, "clear": clear}))
    for i in items:
        print("  ", i.get("preset") or i.get("cfg", {}).get("label") or i)


if __name__ == "__main__":
    main(sys.argv[1:])
