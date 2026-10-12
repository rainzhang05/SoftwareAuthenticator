"""Payment compatibility using only libfido2 1.14.0 public APIs.

1.14 has no payment extension setter/getter. Raw CTAP provisions and checks
metadata; libfido2 must tolerate CM field 0x0C and verify signed unknown
extension bytes. --fixtures verifies actual engine CTAP responses without HID.
"""
import ctypes as C
import ctypes.util
import os
from pathlib import Path
import sys

import ctap as client

RP = "third-party-payment.e2e.example"
NAME = "thirdPartyPayment"
PIN = "4821"


def library():
    path = C.util.find_library("fido2")
    if path is None:
        raise RuntimeError("libfido2 is required")
    lib = C.CDLL(path)
    p, size, integer = C.c_void_p, C.c_size_t, C.c_int
    declarations = {
        "fido_init": (None, [integer]), "fido_strerr": (C.c_char_p, [integer]),
        "fido_assert_new": (p, []), "fido_assert_free": (None, [C.POINTER(p)]),
        "es256_pk_new": (p, []), "es256_pk_free": (None, [C.POINTER(p)]),
        "es256_pk_from_ptr": (integer, [p, p, size]),
        "fido_assert_set_count": (integer, [p, size]),
        "fido_assert_set_rp": (integer, [p, C.c_char_p]),
        "fido_assert_set_clientdata_hash": (integer, [p, p, size]),
        "fido_assert_set_authdata_raw": (integer, [p, size, p, size]),
        "fido_assert_set_sig": (integer, [p, size, p, size]),
        "fido_assert_set_options": (integer, [p, C.c_bool, C.c_bool]),
        "fido_assert_verify": (integer, [p, size, integer, p]),
        "fido_assert_allow_cred": (integer, [p, p, size]),
        "fido_assert_authdata_raw_ptr": (p, [p, size]),
        "fido_assert_authdata_raw_len": (size, [p, size]),
        "fido_assert_sig_ptr": (p, [p, size]), "fido_assert_sig_len": (size, [p, size]),
        "fido_dev_new": (p, []), "fido_dev_free": (None, [C.POINTER(p)]),
        "fido_dev_open": (integer, [p, C.c_char_p]), "fido_dev_close": (integer, [p]),
        "fido_dev_get_assert": (integer, [p, p, C.c_char_p]),
        "fido_credman_rk_new": (p, []), "fido_credman_rk_free": (None, [C.POINTER(p)]),
        "fido_credman_get_dev_rk": (integer, [p, C.c_char_p, p, C.c_char_p]),
        "fido_credman_rk_count": (size, [p]), "fido_credman_rk": (p, [p, size]),
        "fido_cred_id_ptr": (p, [p]), "fido_cred_id_len": (size, [p]),
    }
    for name, (result, arguments) in declarations.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, arguments
    lib.fido_init(0)
    return lib


def check(lib, status):
    assert status == 0, lib.fido_strerr(status).decode("ascii")


def allocation(function):
    pointer = C.c_void_p(function())
    if not pointer.value:
        raise RuntimeError("libfido2 allocation failed")
    return pointer


def verify(lib, public, digest, auth, signature, *, valid=True):
    key, assertion = allocation(lib.es256_pk_new), allocation(lib.fido_assert_new)
    try:
        check(lib, lib.es256_pk_from_ptr(key, public, len(public)))
        check(lib, lib.fido_assert_set_count(assertion, 1))
        check(lib, lib.fido_assert_set_rp(assertion, RP.encode()))
        check(lib, lib.fido_assert_set_clientdata_hash(assertion, digest, len(digest)))
        check(lib, lib.fido_assert_set_authdata_raw(assertion, 0, auth, len(auth)))
        check(lib, lib.fido_assert_set_sig(assertion, 0, signature, len(signature)))
        check(lib, lib.fido_assert_set_options(assertion, True, False))
        result = lib.fido_assert_verify(assertion, 0, client.ES256, key)
        if valid:
            check(lib, result)
        else:
            assert result == -7, lib.fido_strerr(result).decode("ascii")  # FIDO_ERR_INVALID_SIG
    finally:
        lib.fido_assert_free(C.byref(assertion))
        lib.es256_pk_free(C.byref(key))


def fixtures(path):
    lib = library()
    counters = {}
    lines = Path(path).read_text().splitlines()
    assert len(lines) == 12
    for line in lines:
        enabled, rk, requested, digest, public, auth, signature = line.split()
        digest, public, auth, signature = (bytes.fromhex(v) for v in (digest, public, auth, signature))
        data = client.AuthData.parse(auth)
        data.check(RP, up=True, uv=False, at=False)
        expected = {NAME: enabled == "true"} if requested == "true" else None
        assert data.extensions == expected
        key = (enabled, rk)
        counters[key] = counters.get(key, 0) + 1
        assert data.sign_count == counters[key]
        verify(lib, public, digest, auth, signature)
        if requested == "true":
            changed = auth[:-1] + bytes([auth[-1] ^ 1])
            verify(lib, public, digest, changed, signature, valid=False)
    assert set(counters.values()) == {3}
    print("libfido2 verified 12 engine assertions, counters and modified payment bytes")


def hid(path):
    from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
    from fido2.ctap2.pin import PinProtocolV2

    records = []
    # Only one client transport stays open at a time.
    with client.open_device(path) as device:
        ctap = Ctap2(device)
        for rk, enabled in [(True, True), (True, False), (False, True)]:
            credential = client.register(ctap, RP, client.ES256, options={"rk": rk}, extensions={NAME: enabled})
            digest = os.urandom(32)
            response, data = client.authenticate(ctap, credential, extensions={NAME: True}, client_data_hash=digest)
            assert data.extensions == {NAME: enabled}
            assert data.sign_count == 1
            public = credential.public_key[-2] + credential.public_key[-3]
            records.append((credential, public, rk))
            lib = library()
            verify(lib, public, digest, response[2], response[3])
            verify(lib, public, digest, response[2][:-1] + bytes([response[2][-1] ^ 1]), response[3], valid=False)
        protocol = PinProtocolV2()
        pin = ClientPin(ctap, protocol)
        pin.set_pin(PIN)
        token = pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        entries = CredentialManagement(ctap, protocol, token).enumerate_creds(client.sha256(RP.encode()))
        assert {entry[0x0C] for entry in entries} == {False, True}

    lib = library()
    dev, rk_list = allocation(lib.fido_dev_new), allocation(lib.fido_credman_rk_new)
    opened = False
    try:
        check(lib, lib.fido_dev_open(dev, os.fsencode(path)))
        opened = True
        check(lib, lib.fido_credman_get_dev_rk(dev, RP.encode(), rk_list, PIN.encode()))
        ids = set()
        for index in range(lib.fido_credman_rk_count(rk_list)):
            cred = lib.fido_credman_rk(rk_list, index)
            ids.add(C.string_at(lib.fido_cred_id_ptr(cred), lib.fido_cred_id_len(cred)))
        assert ids == {record.credential_id for record, _, rk in records if rk}
        for record, public, _ in records:
            assertion = allocation(lib.fido_assert_new)
            digest = os.urandom(32)
            try:
                check(lib, lib.fido_assert_set_rp(assertion, RP.encode()))
                check(lib, lib.fido_assert_set_clientdata_hash(assertion, digest, len(digest)))
                check(lib, lib.fido_assert_allow_cred(assertion, record.credential_id, len(record.credential_id)))
                check(lib, lib.fido_assert_set_options(assertion, True, False))
                check(lib, lib.fido_dev_get_assert(dev, assertion, None))
                auth = C.string_at(lib.fido_assert_authdata_raw_ptr(assertion, 0), lib.fido_assert_authdata_raw_len(assertion, 0))
                signature = C.string_at(lib.fido_assert_sig_ptr(assertion, 0), lib.fido_assert_sig_len(assertion, 0))
                data = client.AuthData.parse(auth)
                assert data.sign_count == 2
                assert data.extensions is None
                verify(lib, public, digest, auth, signature)
            finally:
                lib.fido_assert_free(C.byref(assertion))
    finally:
        lib.fido_credman_rk_free(C.byref(rk_list))
        if opened:
            check(lib, lib.fido_dev_close(dev))
        lib.fido_dev_free(C.byref(dev))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixtures":
        fixtures(sys.argv[2])
    else:
        hid(sys.argv[1])
