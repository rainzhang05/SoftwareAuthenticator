"""Pinned libfido2 1.14 credential management through its native HID I/O.

Provisioning/raw metadata checks use Python FIDO. The native device always
uses fido_dev_open's default transport; command bytes are never intercepted.
Unsupported COSE decoder failures are checked separately from CTAP support.
"""
import ctypes as C
import os
import sys

from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.pin import PinProtocolV2

import ctap as client
from libfido2_payment import allocation, check, library

PIN = b"4821"
RP = b"a.libfido2-credman.example"
FIDO_ERR_RX_INVALID_CBOR = -4


def native_library():
    lib = library()
    p, size, integer = C.c_void_p, C.c_size_t, C.c_int
    declarations = {
        "fido_credman_metadata_new": (p, []), "fido_credman_metadata_free": (None, [C.POINTER(p)]),
        "fido_credman_get_dev_metadata": (integer, [p, p, C.c_char_p]),
        "fido_credman_rk_existing": (C.c_uint64, [p]), "fido_credman_rk_remaining": (C.c_uint64, [p]),
        "fido_credman_rp_new": (p, []), "fido_credman_rp_free": (None, [C.POINTER(p)]),
        "fido_credman_get_dev_rp": (integer, [p, p, C.c_char_p]),
        "fido_credman_rp_count": (size, [p]), "fido_credman_rp_id": (C.c_char_p, [p, size]),
        "fido_credman_rp_id_hash_len": (size, [p, size]), "fido_credman_rp_id_hash_ptr": (p, [p, size]),
        "fido_credman_del_dev_rk": (integer, [p, p, size, C.c_char_p]),
        "fido_credman_set_dev_rk": (integer, [p, p, C.c_char_p]),
        "fido_cred_new": (p, []), "fido_cred_free": (None, [C.POINTER(p)]),
        "fido_cred_set_id": (integer, [p, p, size]),
        "fido_cred_set_user": (integer, [p, p, size, C.c_char_p, C.c_char_p, C.c_char_p]),
        "fido_cred_user_name": (C.c_char_p, [p]), "fido_cred_display_name": (C.c_char_p, [p]),
        "fido_cred_prot": (integer, [p]), "fido_cred_type": (integer, [p]),
        "fido_cred_largeblob_key_len": (size, [p]), "fido_cred_largeblob_key_ptr": (p, [p]),
    }
    for name, (result, args) in declarations.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, args
    return lib


def prepare(path):
    records = {}
    with client.open_device(path) as device:
        ctap = Ctap2(device)
        assert ctap.info.options["credentialMgmtPreview"]
        capacity = ctap.send_cbor(Ctap2.CMD.GET_INFO)[0x14]
        for index, (rp, alg, enabled) in enumerate([
            (RP.decode(), client.ES256, True), (RP.decode(), client.ES256, False),
            ("b.libfido2-credman.example", client.ES384, False),
            ("c.libfido2-credman.example", client.EDDSA, True),
            ("d.libfido2-credman.example", client.RS256, False),
        ]):
            user = client.user_entity(f"user-{index}")
            credential = client.register(ctap, rp, alg, user=user, options={"rk": True},
                                         extensions={"largeBlobKey": True, "thirdPartyPayment": enabled, "credProtect": 2})
            records[credential.credential_id] = (credential, user, enabled, index)
        protocol = PinProtocolV2()
        pin = ClientPin(ctap, protocol)
        pin.set_pin(PIN.decode())
        token = pin.get_pin_token(PIN.decode())  # legacy issuance, subcommand 5
        for rp in {r[0].rp_id for r in records.values()}:
            fields = {1: client.sha256(rp.encode())}
            from fido2 import cbor
            response = ctap.send_cbor(Ctap2.CMD.CREDENTIAL_MGMT_PRE, {1: 4, 2: fields, 3: 2,
                4: protocol.authenticate(token, b"\x04" + cbor.encode(fields))})
            for entry in [response] + [ctap.send_cbor(Ctap2.CMD.CREDENTIAL_MGMT_PRE, {1: 5}) for _ in range(response[9] - 1)]:
                credential, user, enabled, _ = records[entry[7]["id"]]
                assert entry[6] == user and entry[8] == credential.public_key
                assert entry[12] is enabled and entry[11] == credential.large_blob_key
    return records, capacity


def hid(path):
    records, capacity = prepare(path)
    lib = native_library()
    dev = allocation(lib.fido_dev_new)
    metadata = allocation(lib.fido_credman_metadata_new)
    rps = allocation(lib.fido_credman_rp_new)
    rks = allocation(lib.fido_credman_rk_new)
    update = allocation(lib.fido_cred_new)
    opened = False
    deleted = None
    try:
        check(lib, lib.fido_dev_open(dev, os.fsencode(path)))
        opened = True
        check(lib, lib.fido_credman_get_dev_metadata(dev, metadata, PIN))
        assert lib.fido_credman_rk_existing(metadata) == 5
        assert lib.fido_credman_rk_remaining(metadata) == capacity - 5
        check(lib, lib.fido_credman_get_dev_rp(dev, rps, PIN))
        assert lib.fido_credman_rp_count(rps) == 4
        observed = {}
        for index in range(lib.fido_credman_rp_count(rps)):
            rp = lib.fido_credman_rp_id(rps, index)
            digest = C.string_at(lib.fido_credman_rp_id_hash_ptr(rps, index), lib.fido_credman_rp_id_hash_len(rps, index))
            assert digest == client.sha256(rp)
            check(lib, lib.fido_credman_get_dev_rk(dev, rp, rks, PIN))
            for n in range(lib.fido_credman_rk_count(rks)):
                cred = lib.fido_credman_rk(rks, n)
                identifier = C.string_at(lib.fido_cred_id_ptr(cred), lib.fido_cred_id_len(cred))
                credential, user, _, _ = records[identifier]
                assert lib.fido_cred_type(cred) == credential.alg
                assert lib.fido_cred_prot(cred) == 2
                assert lib.fido_cred_user_name(cred) == user["name"].encode()
                assert C.string_at(lib.fido_cred_largeblob_key_ptr(cred), lib.fido_cred_largeblob_key_len(cred)) == credential.large_blob_key
                observed[identifier] = credential
        assert set(observed) == set(records)
        deleted, (_, user, _, _) = next(iter(records.items()))
        check(lib, lib.fido_cred_set_id(update, deleted, len(deleted)))
        check(lib, lib.fido_cred_set_user(update, user["id"], len(user["id"]), b"Updated", b"Updated Display", None))
        check(lib, lib.fido_credman_set_dev_rk(dev, update, PIN))
        check(lib, lib.fido_credman_get_dev_rk(dev, RP, rks, PIN))
        for n in range(lib.fido_credman_rk_count(rks)):
            cred = lib.fido_credman_rk(rks, n)
            identifier = C.string_at(lib.fido_cred_id_ptr(cred), lib.fido_cred_id_len(cred))
            if identifier == deleted:
                assert lib.fido_cred_user_name(cred) == b"Updated"
                assert lib.fido_cred_display_name(cred) == b"Updated Display"
        check(lib, lib.fido_credman_del_dev_rk(dev, deleted, len(deleted), PIN))
        check(lib, lib.fido_credman_get_dev_metadata(dev, metadata, PIN))
        assert lib.fido_credman_rk_existing(metadata) == 4
        assert lib.fido_credman_rk_remaining(metadata) == capacity - 4
    finally:
        if opened:
            check(lib, lib.fido_dev_close(dev))
        for pointer, free in [(update, lib.fido_cred_free), (rks, lib.fido_credman_rk_free), (rps, lib.fido_credman_rp_free), (metadata, lib.fido_credman_metadata_free), (dev, lib.fido_dev_free)]:
            free(C.byref(pointer))
    with client.open_device(path) as device:
        ctap = Ctap2(device)
        protocol = PinProtocolV2()
        token = ClientPin(ctap, protocol).get_pin_token(PIN.decode(), ClientPin.PERMISSION.CREDENTIAL_MGMT)
        for rp in {r[0].rp_id for r in records.values()}:
            entries = CredentialManagement(ctap, protocol, token).enumerate_creds(client.sha256(rp.encode()))
            for entry in entries:
                credential, _, enabled, _ = records[entry[7]["id"]]
                assert entry[12] is enabled and entry[11] == credential.large_blob_key
                assert entry[8] == credential.public_key
        for identifier, (credential, _, _, _) in records.items():
            if identifier != deleted:
                client.authenticate(ctap, credential)
    print("libfido2 1.14 native HID metadata, RP/credential enumeration, updates, deletion and large-blob metadata passed")


def decoder_limit(path, algorithm=client.ML_DSA_44):
    rp = "decoder.libfido2.example"
    with client.open_device(path) as device:
        ctap = Ctap2(device)
        # A 44 public key fits libfido2 1.14's 2 KiB receive buffer, reaching
        # its unsupported COSE decoder. An 87 key fails earlier with ERR_RX.
        credential = client.register(ctap, rp, algorithm, options={"rk": True})
        ClientPin(ctap, PinProtocolV2()).set_pin(PIN.decode())
    lib = native_library()
    dev, rks = allocation(lib.fido_dev_new), allocation(lib.fido_credman_rk_new)
    opened = False
    try:
        check(lib, lib.fido_dev_open(dev, os.fsencode(path)))
        opened = True
        status = lib.fido_credman_get_dev_rk(dev, rp.encode(), rks, PIN)
        assert status == FIDO_ERR_RX_INVALID_CBOR, lib.fido_strerr(status).decode()
    finally:
        if opened:
            check(lib, lib.fido_dev_close(dev))
        lib.fido_credman_rk_free(C.byref(rks))
        lib.fido_dev_free(C.byref(dev))
    with client.open_device(path) as device:
        ctap = Ctap2(device)
        protocol = PinProtocolV2()
        token = ClientPin(ctap, protocol).get_pin_token(PIN.decode())
        from fido2 import cbor
        fields = {1: client.sha256(rp.encode())}
        entry = ctap.send_cbor(Ctap2.CMD.CREDENTIAL_MGMT_PRE, {1: 4, 2: fields, 3: 2,
            4: protocol.authenticate(token, b"\x04" + cbor.encode(fields))})
        assert entry[7]["id"] == credential.credential_id and entry[8] == credential.public_key
        client.authenticate(ctap, credential)
    print(f"libfido2 decoder limitation for {client.NAMES[algorithm]} is separate from successful authenticator enumeration and signing")


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[2] == "--decoder-limit":
        decoder_limit(sys.argv[1], int(sys.argv[3]) if len(sys.argv) > 3 else client.ML_DSA_44)
    else:
        hid(sys.argv[1])
