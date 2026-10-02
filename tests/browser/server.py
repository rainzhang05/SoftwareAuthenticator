#!/usr/bin/env python3
"""Local WebAuthn relying party for testing pqkey in real browsers.

Serves http://localhost:8080 (RP ID "localhost", a secure context) on the
loopback interfaces only. Every registration and sign-in is verified twice:

  * by python-fido2's Fido2Server (register_complete / authenticate_complete)
    plus python-fido2's attestation verifier for the statement's format;
  * independently, with the helpers of the end-to-end suite
    (tests/e2e/ctap.py): AuthData.parse/check, check_public_key,
    verify_signature (pyca/cryptography + OpenSSL ML-DSA) and verify_attestation.

Everything is appended to results.jsonl in the data directory ($RP_DATA, by
default tests/browser/data/); credentials are kept in db.json there, so they
survive a restart of this server. See README.md.
"""
from __future__ import annotations

import sys

from pathlib import Path  # noqa: E402

sys.dont_write_bytecode = True  # never write __pycache__ into the repository
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "e2e"))

import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import secrets  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import traceback  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

import ctap as rc  # noqa: E402  (tests/e2e/ctap.py)
from fido2 import cbor  # noqa: E402
from fido2.attestation import Attestation  # noqa: E402
from fido2.server import Fido2Server  # noqa: E402
from fido2.webauthn import (  # noqa: E402
    AttestedCredentialData,
    AuthenticatorData,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
)

HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("RP_DATA") or HERE / "data")
DB_PATH = DATA / "db.json"
RESULTS = DATA / "results.jsonl"
RP_ID = "localhost"
PORT = int(os.environ.get("RP_PORT", "8080"))
LOCK = threading.RLock()
PENDING: dict[str, dict] = {}  # ceremony id -> state
QUEUES: dict[str, list] = {"firefox": [], "chrome": []}  # remote-control queues per browser family
SEEN: dict[str, float] = {}  # browser family -> last poll time


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_db() -> dict:
    if DB_PATH.exists():
        return json.loads(DB_PATH.read_text())
    return {"users": {}, "prf": {}}


def save_db(db: dict) -> None:
    tmp = DB_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=1))
    tmp.replace(DB_PATH)


def log_result(entry: dict) -> None:
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}
    with LOCK, RESULTS.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    status = entry.get("outcome")
    print(f"[{entry['time']}] {entry.get('kind')} {entry.get('label')!r}: {status} {entry.get('summary', '')}", flush=True)


def jsonable(v):
    if isinstance(v, bytes):
        return {"hex": v.hex()} if len(v) <= 64 else {"hex_prefix": v[:32].hex(), "len": len(v)}
    if isinstance(v, dict):
        return {str(k): jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [jsonable(x) for x in v]
    return v


class Checks:
    """Collects named checks; a failing check does not stop the others."""

    def __init__(self):
        self.items: list[dict] = []

    def run(self, name, fn):
        try:
            detail = fn()
            self.items.append({"check": name, "ok": True, **({"detail": detail} if detail is not None else {})})
            return True
        except Exception as e:  # noqa: BLE001
            self.items.append({"check": name, "ok": False, "error": f"{type(e).__name__}: {e}"})
            return False

    def note(self, name, detail):
        self.items.append({"check": name, "ok": None, "detail": detail})

    @property
    def ok(self):
        return all(i["ok"] is not False for i in self.items)


def flags_str(f: int) -> str:
    names = [(0x01, "UP"), (0x04, "UV"), (0x08, "BE"), (0x10, "BS"), (0x40, "AT"), (0x80, "ED")]
    return f"{f:#04x} " + "|".join(n for b, n in names if f & b)


# --------------------------------------------------------------------- ceremonies


def register_options(req: dict) -> dict:
    username = req["username"].strip()
    algs = [int(a) for a in req.get("algs", [rc.ES256])]
    with LOCK:
        db = load_db()
        user = db["users"].setdefault(username, {"id": b64u(secrets.token_bytes(16)), "credentials": []})
        save_db(db)
    server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name="pqkey local test RP"),
                         attestation=req.get("attestation") or None)
    server.allowed_algorithms = [PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=a)
                                 for a in algs]
    exclude = None
    if req.get("excludeExisting"):
        exclude = [{"type": "public-key", "id": unb64u(c["id"])} for c in user["credentials"]]
    opts, state = server.register_begin(
        {"id": unb64u(user["id"]), "name": username, "displayName": req.get("displayName") or username},
        credentials=exclude,
        resident_key_requirement=req.get("residentKey") or None,
        user_verification=req.get("userVerification") or None,
        authenticator_attachment=req.get("attachment") or None,
    )
    pk = dict(opts)["publicKey"]
    ext = {}
    if req.get("credProps"):
        ext["credProps"] = True
    if req.get("prf"):
        ext["prf"] = {}
        if req.get("prfSalt1"):
            ext["prf"] = {"eval": {"first": b64u(hashlib.sha256(req["prfSalt1"].encode()).digest())}}
    if req.get("credProtect"):
        ext["credentialProtectionPolicy"] = req["credProtect"]
        ext["enforceCredentialProtectionPolicy"] = bool(req.get("enforceCredProtect"))
    if ext:
        pk["extensions"] = ext
    if req.get("hints"):
        pk["hints"] = req["hints"]
    pk["timeout"] = int(req.get("timeout") or 60000)
    cid = secrets.token_hex(8)
    with LOCK:
        PENDING[cid] = {"kind": "register", "state": state, "req": req, "username": username, "algs": algs,
                        "options": pk, "issued": time.time()}
    return {"ceremonyId": cid, "publicKey": pk}


def register_verify(body: dict) -> dict:
    with LOCK:
        p = PENDING.pop(body["ceremonyId"])
    req, cred = p["req"], body["credential"]
    checks = Checks()
    server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name="pqkey local test RP"))
    resp = {"id": cred["id"], "rawId": cred["rawId"], "type": cred["type"],
            "response": {"clientDataJSON": cred["response"]["clientDataJSON"],
                         "attestationObject": cred["response"]["attestationObject"]},
            "clientExtensionResults": {}}
    if cred.get("authenticatorAttachment"):
        resp["authenticatorAttachment"] = cred["authenticatorAttachment"]
    auth = {}
    checks.run("python-fido2 Fido2Server.register_complete (type, origin, challenge, rpIdHash, UP, UV-if-required)",
               lambda: auth.setdefault("ad", server.register_complete(p["state"], resp)) and None)
    client_data_json = unb64u(cred["response"]["clientDataJSON"])
    client_data = json.loads(client_data_json)
    att = cbor.decode(unb64u(cred["response"]["attestationObject"]))
    fmt, auth_data_raw, att_stmt = att["fmt"], att["authData"], att["attStmt"]
    cdh = rc.sha256(client_data_json)
    ad = rc.AuthData.parse(auth_data_raw)
    alg = ad.public_key.get(3) if ad.public_key else None
    checks.note("clientData", {k: client_data.get(k) for k in ("type", "origin", "crossOrigin")})
    checks.note("attestation format", fmt)
    checks.note("attStmt keys", sorted(att_stmt))
    checks.note("flags", flags_str(ad.flags))
    checks.note("signCount", ad.sign_count)
    checks.note("AAGUID", ad.aaguid.hex() if ad.aaguid else None)
    checks.note("credential ID", {"len": len(ad.credential_id), "marker": f"{ad.credential_id[0]:#04x}",
                                  "b64u": b64u(ad.credential_id)})
    checks.note("authenticator extension outputs", jsonable(ad.extensions))
    checks.note("client extension results", cred.get("clientExtensionResults"))
    checks.note("transports / attachment", {"transports": cred.get("transports"),
                                            "authenticatorAttachment": cred.get("authenticatorAttachment")})
    checks.note("public key algorithm", f"{alg} ({rc.NAMES.get(alg, '?')})")
    checks.note("client-side parsing (getPublicKeyAlgorithm / getPublicKey / toJSON)", cred.get("clientSide"))
    checks.run("algorithm is one the RP offered", lambda: _assert(alg in p["algs"], f"{alg} not in {p['algs']}"))
    first = next(a for a in p["algs"] if a in rc.NAMES)
    checks.note("algorithm choice (RP order; a client may strip algorithms it does not know, e.g. Firefox and ML-DSA)",
                {"rp_order": p["algs"], "first_pqkey_supported": first, "picked": alg,
                 "matches_rp_order": alg == first})
    checks.run("rc.check_public_key (COSE structure, RFC 9964 for ML-DSA)", lambda: rc.check_public_key(ad.public_key, alg))
    checks.run("rpIdHash == SHA-256('localhost')", lambda: _assert(ad.rp_id_hash == rc.sha256(RP_ID.encode())))
    uv_required = req.get("userVerification") == "required"
    checks.run("flags: UP=1, AT=1, BE=BS=0, reserved=0" + (", UV=1 (required)" if uv_required else ""),
               lambda: (_assert(ad.flags & rc.FLAG_UP, "UP"), _assert(ad.flags & rc.FLAG_AT, "AT"),
                        _assert(not ad.flags & 0x3A, "reserved/BE/BS"),
                        uv_required and _assert(ad.flags & rc.FLAG_UV, "UV")) and None)
    checks.run("ED flag iff authenticator extension outputs present",
               lambda: _assert(bool(ad.flags & rc.FLAG_ED) == bool(ad.extensions)))
    if fmt != "none":
        checks.run(f"python-fido2 {fmt} attestation verify",
                   lambda: str(Attestation.for_type(fmt)().verify(att_stmt, AuthenticatorData(auth_data_raw), cdh).attestation_type))
    checks.run(f"rc.verify_attestation ({fmt}; self attestation verified with the credential key)",
               lambda: rc.verify_attestation({1: fmt, 2: auth_data_raw, 3: att_stmt}, ad.public_key, cdh))
    rk_cp = (cred.get("clientExtensionResults") or {}).get("credProps", {}).get("rk")
    expected_disc = {33: True, 107: False}.get(len(ad.credential_id))
    checks.run("credential ID layout per architecture.md (33 B 0x01 = discoverable, 107 B 0x02 = sealed)",
               lambda: _assert((len(ad.credential_id), ad.credential_id[0]) in ((33, 1), (107, 2)),
                               f"{len(ad.credential_id)} bytes, marker {ad.credential_id[0]:#04x}"))
    if rk_cp is not None:
        checks.run("credProps.rk matches the credential ID kind", lambda: _assert(rk_cp == expected_disc,
                                                                                 f"credProps.rk={rk_cp}, id kind disc={expected_disc}"))
    if ad.extensions and "credProtect" in ad.extensions and req.get("credProtect"):
        want = {"userVerificationOptional": 1, "userVerificationOptionalWithCredentialIDList": 2,
                "userVerificationRequired": 3}[req["credProtect"]]
        checks.run(f"credProtect output == requested level {want}", lambda: _assert(ad.extensions["credProtect"] == want,
                                                                                    f"got {ad.extensions['credProtect']}"))
    record = {"id": b64u(ad.credential_id), "alg": alg, "disc": expected_disc, "credProps_rk": rk_cp,
              "acd": bytes(auth["ad"].credential_data).hex() if auth.get("ad") else None,
              "cose": cbor.encode(ad.public_key).hex(), "signCount": ad.sign_count,
              "created": time.strftime("%H:%M:%S"), "label": req.get("label"),
              "credProtect": (ad.extensions or {}).get("credProtect"), "browser": body.get("ua", "")[:80]}
    if checks.ok:
        with LOCK:
            db = load_db()
            u = db["users"][p["username"]]
            u["credentials"].append(record)
            save_db(db)
    outcome = "PASS" if checks.ok else "FAIL"
    cs = cred.get("clientSide") or {}
    summary = f"{rc.NAMES.get(alg, alg)} {'disc' if expected_disc else 'non-disc'} id={len(ad.credential_id)}B " \
              f"client:getPublicKey={cs.get('getPublicKey')!s} " \
              f"fmt={fmt} flags={flags_str(ad.flags)} signCount={ad.sign_count} ext={jsonable(ad.extensions)}"
    entry = {"kind": "register", "label": req.get("label"), "ua": body.get("ua"), "elapsed_ms": body.get("elapsed_ms"),
             "request": {k: req.get(k) for k in ("username", "algs", "residentKey", "userVerification", "attestation",
                                                 "credProps", "prf", "credProtect", "enforceCredProtect",
                                                 "excludeExisting", "hints", "attachment")},
             "outcome": outcome, "summary": summary, "checks": checks.items}
    log_result(entry)
    return entry


def login_options(req: dict) -> dict:
    username = (req.get("username") or "").strip()
    mode = req.get("allow", "user")
    with LOCK:
        db = load_db()
    allow = None
    if mode == "user":
        if username not in db["users"]:
            raise ValueError(f"user {username!r} has no credentials at this RP yet (register first)")
        allow = [{"type": "public-key", "id": unb64u(c["id"])} for c in db["users"][username]["credentials"]]
    elif mode.startswith("cred:"):
        allow = [{"type": "public-key", "id": unb64u(mode[5:])}]
    server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name="pqkey local test RP"))
    ext = {}
    if req.get("prfSalt1"):
        ev = {"first": b64u(hashlib.sha256(req["prfSalt1"].encode()).digest())}
        if req.get("prfSalt2"):
            ev["second"] = b64u(hashlib.sha256(req["prfSalt2"].encode()).digest())
        ext["prf"] = {"eval": ev}
    opts, state = server.authenticate_begin(allow, user_verification=req.get("userVerification") or None,
                                            extensions=ext or None)
    pk = dict(opts)["publicKey"]
    if allow is not None and not allow:
        pk["allowCredentials"] = []
    if req.get("hints"):
        pk["hints"] = req["hints"]
    pk["timeout"] = int(req.get("timeout") or 60000)
    cid = secrets.token_hex(8)
    with LOCK:
        PENDING[cid] = {"kind": "login", "state": state, "req": req, "options": pk, "issued": time.time()}
    return {"ceremonyId": cid, "publicKey": pk}


def login_verify(body: dict) -> dict:
    with LOCK:
        p = PENDING.pop(body["ceremonyId"])
        db = load_db()
    req, cred = p["req"], body["credential"]
    checks = Checks()
    cred_id = cred["rawId"]
    owner, stored = None, None
    for name, u in db["users"].items():
        for c in u["credentials"]:
            if c["id"] == cred_id:
                owner, stored = name, c
    checks.run("credential is registered at this RP", lambda: _assert(stored is not None, f"unknown id {cred_id[:16]}…"))
    if stored is None:
        entry = {"kind": "login", "label": req.get("label"), "outcome": "FAIL", "summary": "unknown credential",
                 "checks": checks.items, "ua": body.get("ua")}
        log_result(entry)
        return entry
    resp = {"id": cred["id"], "rawId": cred["rawId"], "type": cred["type"],
            "response": {k: cred["response"][k] for k in ("clientDataJSON", "authenticatorData", "signature")
                         if cred["response"].get(k) is not None},
            "clientExtensionResults": {}}
    if cred["response"].get("userHandle"):
        resp["response"]["userHandle"] = cred["response"]["userHandle"]
    if stored.get("acd"):
        checks.run("python-fido2 Fido2Server.authenticate_complete (type, origin, challenge, rpIdHash, UP, signature)",
                   lambda: server_auth(p["state"], stored, resp) and None)
    client_data_json = unb64u(cred["response"]["clientDataJSON"])
    auth_data_raw = unb64u(cred["response"]["authenticatorData"])
    sig = unb64u(cred["response"]["signature"])
    ad = rc.AuthData.parse(auth_data_raw)
    cose = cbor.decode(bytes.fromhex(stored["cose"]))
    alg = cose[3]
    checks.note("credential", {"owner": owner, "alg": rc.NAMES.get(alg, alg), "discoverable": stored.get("disc"),
                               "registered": stored.get("created"), "label": stored.get("label")})
    checks.note("flags", flags_str(ad.flags))
    checks.note("signCount", {"now": ad.sign_count, "stored": stored.get("signCount")})
    checks.note("signature length", len(sig))
    checks.note("userHandle", cred["response"].get("userHandle"))
    checks.note("authenticator extension outputs", jsonable(ad.extensions))
    checks.note("client extension results", cred.get("clientExtensionResults"))
    checks.run(f"rc.verify_signature over authData||SHA-256(clientDataJSON) ({rc.NAMES.get(alg)})",
               lambda: rc.verify_signature(cose, auth_data_raw + rc.sha256(client_data_json), sig))
    checks.run("rpIdHash == SHA-256('localhost')", lambda: _assert(ad.rp_id_hash == rc.sha256(RP_ID.encode())))
    uv_required = req.get("userVerification") == "required"
    checks.run("flags: UP=1, AT=0, BE=BS=0, reserved=0" + (", UV=1 (required)" if uv_required else ""),
               lambda: (_assert(ad.flags & rc.FLAG_UP, "UP"), _assert(not ad.flags & rc.FLAG_AT, "AT"),
                        _assert(not ad.flags & 0x3A, "reserved/BE/BS"),
                        uv_required and _assert(ad.flags & rc.FLAG_UV, "UV")) and None)
    checks.run("ED flag iff authenticator extension outputs present",
               lambda: _assert(bool(ad.flags & rc.FLAG_ED) == bool(ad.extensions)))
    # A discoverable credential has a counter of its own; non-discoverable
    # ones share the key's global counter. Either only grows (architecture.md).
    checks.run("signCount increased since this credential's last sign-in",
               lambda: _assert(ad.sign_count > (stored.get("signCount") or 0),
                               f"{ad.sign_count} <= {stored.get('signCount')}"))
    if cred["response"].get("userHandle"):
        checks.run("userHandle is the user's id", lambda: _assert(cred["response"]["userHandle"] ==
                                                                db["users"][owner]["id"]))
    elif req.get("allow") == "empty":
        checks.run("userHandle present for a discoverable sign-in", lambda: _assert(False, "missing"))
    prf = (cred.get("clientExtensionResults") or {}).get("prf", {}).get("results")
    if prf and req.get("prfSalt1"):
        uv = bool(ad.flags & rc.FLAG_UV)
        for slot, salt in (("first", req.get("prfSalt1")), ("second", req.get("prfSalt2"))):
            if not salt or slot not in prf:
                continue
            key = f"{cred_id}|{salt}|uv={uv}"
            with LOCK:
                db2 = load_db()
                prev = db2["prf"].get(key)
                if prev is None:
                    db2["prf"][key] = prf[slot]
                    save_db(db2)
            others = {k: v for k, v in db2["prf"].items() if k.startswith(cred_id + "|") and k != key}
            checks.note(f"PRF {slot} (salt {salt!r}, UV={uv})", {"output": prf[slot], "previous": prev})
            if prev is not None:
                checks.run(f"PRF {slot}: same salt+UV gives the same output as before",
                           lambda prev=prev, v=prf[slot]: _assert(prev == v, "different"))
            clash = [k for k, v in others.items() if v == prf[slot]]
            checks.run(f"PRF {slot}: differs from every other salt/UV output of this credential",
                       lambda clash=clash: _assert(not clash, f"equal to {clash}"))
    if checks.ok:
        with LOCK:
            db = load_db()
            for c in db["users"][owner]["credentials"]:
                if c["id"] == cred_id:
                    c["signCount"] = ad.sign_count
            save_db(db)
    outcome = "PASS" if checks.ok else "FAIL"
    summary = f"{owner} {rc.NAMES.get(alg, alg)} sig={len(sig)}B flags={flags_str(ad.flags)} " \
              f"signCount={ad.sign_count} ext={jsonable(ad.extensions)}"
    entry = {"kind": "login", "label": req.get("label"), "ua": body.get("ua"), "elapsed_ms": body.get("elapsed_ms"),
             "request": {k: req.get(k) for k in ("username", "allow", "userVerification", "prfSalt1", "prfSalt2", "hints")},
             "outcome": outcome, "summary": summary, "checks": checks.items}
    log_result(entry)
    return entry


def server_auth(state, stored, resp):
    server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name="pqkey local test RP"))
    return server.authenticate_complete(state, [AttestedCredentialData(bytes.fromhex(stored["acd"]))], resp)


def _assert(cond, msg="assertion failed"):
    if not cond:
        raise AssertionError(msg)


# --------------------------------------------------------------------- HTTP


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path == "/api/db":
            with LOCK:
                db = load_db()
            return self._send(200, {"users": {n: {"id": u["id"], "credentials": [
                {k: c.get(k) for k in ("id", "alg", "disc", "credProps_rk", "signCount", "created", "label",
                                       "credProtect", "browser")} for c in u["credentials"]]}
                for n, u in db["users"].items()}})
        if self.path.startswith("/api/next"):
            fam = "firefox" if "firefox" in self.path else "chrome"
            with LOCK:
                SEEN[fam] = time.time()
                item = QUEUES[fam].pop(0) if QUEUES[fam] else None
            return self._send(200, {"item": item})
        if self.path == "/api/queue":
            with LOCK:
                return self._send(200, {"queues": QUEUES, "seen_s_ago": {k: round(time.time() - v, 1) for k, v in SEEN.items()}})
        if self.path == "/api/results":
            lines = RESULTS.read_text().splitlines()[-30:] if RESULTS.exists() else []
            return self._send(200, [json.loads(x) for x in lines][::-1])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            routes = {"/api/register/options": register_options, "/api/register/verify": register_verify,
                      "/api/login/options": login_options, "/api/login/verify": login_verify,
                      "/api/client-error": client_error, "/api/forget": forget, "/api/enqueue": enqueue}
            fn = routes.get(self.path)
            if fn is None:
                return self._send(404, {"error": "not found"})
            self._send(200, fn(body))
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def client_error(body: dict) -> dict:
    with LOCK:
        p = PENDING.pop(body.get("ceremonyId", ""), None)
    entry = {"kind": body.get("kind", "?") + "-error", "label": body.get("label"), "ua": body.get("ua"),
             "elapsed_ms": body.get("elapsed_ms"), "outcome": body.get("name"),
             "summary": f"{body.get('name')}: {body.get('message')} after {body.get('elapsed_ms')} ms",
             "request": (p or {}).get("req")}
    log_result(entry)
    return entry


def enqueue(body: dict) -> dict:
    """Queue ceremonies for a browser page in remote-control mode (driven from the tester's shell)."""
    with LOCK:
        if body.get("clear"):
            QUEUES[body["browser"]].clear()
        QUEUES[body["browser"]].extend(body.get("items", []))
        return {"queued": len(QUEUES[body["browser"]])}


def forget(body: dict) -> dict:
    """Drop credentials from the RP's database (for example after a key reset)."""
    with LOCK:
        db = load_db()
        if body.get("all"):
            db = {"users": {}, "prf": {}}
        elif body.get("id"):
            for u in db["users"].values():
                u["credentials"] = [c for c in u["credentials"] if c["id"] != body["id"]]
        save_db(db)
    log_result({"kind": "rp-forget", "label": body.get("label"), "outcome": "done", "summary": json.dumps(body)})
    return {"ok": True}


class V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


if __name__ == "__main__":
    DATA.mkdir(parents=True, exist_ok=True)
    servers = [ThreadingHTTPServer(("127.0.0.1", PORT), Handler)]
    try:
        servers.append(V6Server(("::1", PORT), Handler))
    except OSError as e:
        print(f"no ::1 listener: {e}")
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print(f"pqkey test RP on http://localhost:{PORT}/ (results: {RESULTS})", flush=True)
    servers[0].serve_forever()
