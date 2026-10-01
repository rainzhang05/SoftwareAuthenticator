#!/usr/bin/env python3
"""Decode CTAPHID/CTAP2 traffic from an strace of `pqkey run`.

  strace -f -tt -e trace=read,write -e signal=none -s 4400 -xx -o TRACE pqkey run
  python3 contrib/debug/uhid_strace_decode.py TRACE

Reads of 4376 bytes from /dev/uhid are uhid_event structs: UHID_OUTPUT (6)
carries a host->device report (data[4096], size u16, rtype u8). Writes of
UHID_INPUT2 (12) carry device->host reports (size u16, data[4096]).
Keepalives are left out. Needs python-fido2 (tests/e2e/requirements.txt).

A trace holds relying party IDs, user names and IDs, and the encrypted PIN
messages of every request: keep it private.
"""
import re
import struct
import sys

from fido2 import cbor  # noqa: E402

LINE = re.compile(r'^(\d+)\s+(?:(\d\d:\d\d:\d\d\.\d+)\s+)?(read|write)\((\d+), "((?:\\x[0-9a-f]{2})*)"(?:\.\.\.)?, (\d+)\)\s+=\s+(-?\d+)')
CTAP = {0x01: "makeCredential", 0x02: "getAssertion", 0x04: "getInfo", 0x06: "clientPIN", 0x07: "reset",
        0x08: "getNextAssertion", 0x0A: "credentialManagement", 0x0B: "selection"}
MC = {1: "clientDataHash", 2: "rp", 3: "user", 4: "pubKeyCredParams", 5: "excludeList", 6: "extensions",
      7: "options", 8: "pinUvAuthParam", 9: "pinUvAuthProtocol", 10: "enterpriseAttestation",
      11: "attestationFormatsPreference"}
GA = {1: "rpId", 2: "clientDataHash", 3: "allowList", 4: "extensions", 5: "options", 6: "pinUvAuthParam",
      7: "pinUvAuthProtocol"}
CMDS = {0x01: "PING", 0x03: "MSG", 0x06: "INIT", 0x10: "CBOR", 0x11: "CANCEL", 0x3B: "KEEPALIVE", 0x3F: "ERROR"}


def unhex(s):
    return bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-f]{2})", s))


def short(v):
    if isinstance(v, bytes):
        return f"h'{v.hex()}'" if len(v) <= 40 else f"h'{v[:16].hex()}…' ({len(v)} bytes)"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{short(k)}: {short(x)}" for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(short(x) for x in v) + "]"
    return repr(v)


class Assembler:
    """Reassembles CTAPHID messages per channel (packets of channels interleave)."""

    def __init__(self, direction):
        self.direction = direction
        self.cur = {}

    def feed(self, frame):
        cid, b4 = frame[:4], frame[4]
        if b4 & 0x80:
            cmd = b4 & 0x7F
            bcnt = struct.unpack(">H", frame[5:7])[0]
            self.cur[cid] = [cmd, bcnt, bytearray(frame[7:7 + bcnt])]
        elif cid in self.cur:
            self.cur[cid][2] += frame[5:]
        else:
            return None
        cmd, bcnt, data = self.cur[cid]
        if len(data) >= bcnt:
            del self.cur[cid]
            return cid.hex(), cmd, bytes(data[:bcnt])
        return None


def describe(direction, cid, cmd, payload, last_req):
    name = CMDS.get(cmd, hex(cmd))
    if cmd == 0x3B:
        return None  # keepalives
    if cmd != 0x10:
        return f"{direction} cid={cid} {name} {payload.hex()[:64]}"
    if direction == ">>":
        c = payload[0]
        params = cbor.decode(payload[1:]) if len(payload) > 1 else None
        names = MC if c == 0x01 else GA if c in (0x02,) else {}
        last_req[0] = c
        out = [f">> cid={cid} CTAP {CTAP.get(c, hex(c))} ({len(payload)} bytes)"]
        if isinstance(params, dict):
            for k, v in params.items():
                out.append(f"     {k} {names.get(k, '')}: {short(v)}")
        return "\n".join(out)
    status = payload[0]
    out = [f"<< cid={cid} status=0x{status:02x} ({len(payload)} bytes)"]
    if len(payload) > 1 and last_req[0] != 0x04:
        try:
            resp = cbor.decode(payload[1:])
            for k, v in resp.items():
                out.append(f"     {k}: {short(v)}")
        except Exception as e:  # noqa: BLE001
            out.append(f"     (undecodable: {e})")
    return "\n".join(out)


RESUMED = re.compile(r'^(\d+)\s+(?:(\d\d:\d\d:\d\d\.\d+)\s+)?<\.\.\. (read|write) resumed>(.*)$')
UNFINISHED = re.compile(r'^(\d+)\s+(?:(\d\d:\d\d:\d\d\.\d+)\s+)?(read|write)\((.*) <unfinished \.\.\.>$')


def lines(path):
    """Join strace -f's split '<unfinished ...>' / '<... resumed>' lines."""
    pending = {}
    for line in open(path, errors="replace"):
        line = line.rstrip("\n")
        u = UNFINISHED.match(line)
        if u:
            pending[u.group(1)] = f"{u.group(1)} {u.group(2) or ''} {u.group(3)}({u.group(4)}"
            continue
        r = RESUMED.match(line)
        if r and r.group(1) in pending:
            yield pending.pop(r.group(1)) + r.group(4)
            continue
        yield line


def main(path):
    host, dev = Assembler(">>"), Assembler("<<")
    last_req = [None]
    for line in lines(path):
        m = LINE.match(line)
        if not m:
            continue
        _pid, ts, op, _fd, data, _count, ret = m.groups()
        stamp = (ts or "")[:12]
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
                d = describe(">>", *msg, last_req)
                d and print(stamp, d)
        elif op == "write" and etype == 12:
            size = struct.unpack("<H", raw[4:6])[0]
            rep = raw[6:6 + size]
            msg = dev.feed(rep) if len(rep) == 64 else None
            if msg:
                d = describe("<<", *msg, last_req)
                d and print(stamp, d)


if __name__ == "__main__":
    main(sys.argv[1])
