#!/usr/bin/env python3
"""Verify every makeCredential / getAssertion found in an strace of pqkey,
offline, with the end-to-end suite's checks (tests/e2e/ctap.py).

  contrib/debug/verify_trace.py TRACE... [--since HH:MM:SS]

TRACE is made as uhid_strace_decode.py describes.

For makeCredential: parse authData, check the COSE key, verify the packed
self-attestation over authData || clientDataHash (from the request).
For getAssertion: verify the signature with the public key of the matching
registration seen earlier in the same trace(s).
"""
import sys

from pathlib import Path  # noqa: E402

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "tests" / "e2e"))
sys.path.insert(0, str(HERE))

import struct  # noqa: E402

import ctap as rc  # noqa: E402
from fido2 import cbor  # noqa: E402
from uhid_strace_decode import LINE, Assembler, lines, unhex  # noqa: E402

NAMES = {-7: "ES256", -48: "ML-DSA-44", -49: "ML-DSA-65", -50: "ML-DSA-87"}


def messages(path):
    host, dev = Assembler(">>"), Assembler("<<")
    for line in lines(path):
        m = LINE.match(line)
        if not m:
            continue
        _pid, ts, op, _fd, data, _count, ret = m.groups()
        raw = unhex(data)
        if int(ret) < 6 or len(raw) < 6:
            continue
        etype = struct.unpack("<I", raw[:4])[0]
        if op == "read" and etype == 6 and len(raw) >= 4 + 4096 + 3:
            size = struct.unpack("<H", raw[4 + 4096:4 + 4098])[0]
            rep = raw[4:4 + size]
            if len(rep) == 65 and rep[0] == 0:
                rep = rep[1:]
            msg = host.feed(rep) if len(rep) == 64 else None
            if msg:
                yield ts, ">>", *msg
        elif op == "write" and etype == 12:
            size = struct.unpack("<H", raw[4:6])[0]
            rep = raw[6:6 + size]
            msg = dev.feed(rep) if len(rep) == 64 else None
            if msg:
                yield ts, "<<", *msg


def main(paths, since):
    keys = {}  # credential id -> cose key
    pending = {}  # cid -> (ctap cmd, params)
    for path in paths:
        for ts, d, cid, cmd, payload in messages(path):
            if cmd != 0x10:
                continue
            if d == ">>":
                params = cbor.decode(payload[1:]) if len(payload) > 1 else {}
                pending[cid] = (payload[0], params)
                continue
            req = pending.pop(cid, None)
            if not req or payload[0] != 0 or req[0] not in (0x01, 0x02):
                continue
            c, params = req
            resp = cbor.decode(payload[1:])
            show = since is None or (ts or "") >= since
            try:
                if c == 0x01:
                    ad = rc.AuthData.parse(resp[2])
                    alg = ad.public_key[3]
                    rc.check_public_key(ad.public_key, alg)
                    rc.verify_attestation(resp, ad.public_key, params[1])
                    keys[ad.credential_id] = ad.public_key
                    if show:
                        print(f"{ts} makeCredential rp={params[2]['id']} {NAMES[alg]} fmt={resp[1]} "
                              f"id={len(ad.credential_id)}B flags={ad.flags:#04x} ext={ad.extensions} "
                              f"resp={len(payload)}B -> attestation signature VALID, COSE key OK")
                else:
                    cred_id = resp[1]["id"]
                    ad = rc.AuthData.parse(resp[2])
                    key = keys.get(cred_id)
                    if key is None:
                        if show:
                            print(f"{ts} getAssertion rp={params[1]} id={cred_id[:6].hex()}… (registration not in trace; skipped)")
                        continue
                    rc.verify_signature(key, resp[2] + params[2], resp[3])
                    if show:
                        print(f"{ts} getAssertion   rp={params[1]} {NAMES[key[3]]} id={len(cred_id)}B "
                              f"flags={ad.flags:#04x} signCount={ad.sign_count} sig={len(resp[3])}B "
                              f"user={resp.get(4)} resp={len(payload)}B -> signature VALID")
            except Exception as e:  # noqa: BLE001
                print(f"{ts} {'makeCredential' if c == 1 else 'getAssertion'} FAILED: {type(e).__name__}: {e}")


if __name__ == "__main__":
    args = sys.argv[1:]
    since = None
    if "--since" in args:
        i = args.index("--since")
        since = args[i + 1]
        del args[i:i + 2]
    main(args, since)
