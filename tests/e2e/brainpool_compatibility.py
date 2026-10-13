"""Brainpool engine/OpenSSL fixtures and libfido2 1.14 public-API limits."""
import argparse
import ctypes as C
import importlib.util
import os
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils
from fido2 import cbor
import ctap as client
from libfido2_payment import allocation, check, library


def native_types():
    lib = library()
    lib.fido_cred_new.restype = C.c_void_p
    lib.fido_cred_free.argtypes = [C.POINTER(C.c_void_p)]
    lib.fido_cred_set_type.argtypes = [C.c_void_p, C.c_int]
    for algorithm in (client.ESB256, client.ESB384):
        credential = allocation(lib.fido_cred_new)
        try:
            assert lib.fido_cred_set_type(credential, algorithm) == -7  # INVALID_ARGUMENT
        finally:
            lib.fido_cred_free(C.byref(credential))
    return lib


def fixtures(path):
    browser_path = Path(__file__).resolve().parent.parent / "browser" / "server.py"
    spec = importlib.util.spec_from_file_location("brainpool_browser_fixture", browser_path)
    browser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(browser)
    lines = Path(path).read_text().splitlines()
    assert len(lines) == 8
    for line in lines:
        alg, rk, payment, digest, *responses = line.split()
        alg, rk, payment = int(alg), rk == "true", payment == "true"
        digest = bytes.fromhex(digest)
        registration, *assertions = [cbor.decode(bytes.fromhex(v)[1:]) for v in responses]
        data = client.AuthData.parse(registration[2])
        assert len(data.credential_id) == 33 and data.credential_id[0] == int(rk)
        assert browser.credential_modality(data.credential_id) == rk
        client.check_public_key(data.public_key, alg)
        client.verify_attestation(registration, data.public_key, digest)
        assert data.extensions == {"credBlob": True, "hmac-secret": True}
        for count, response in enumerate(assertions, 1):
            auth = client.AuthData.parse(response[2])
            auth.check("brainpool.e2e.example", up=True, uv=False, at=False)
            assert auth.sign_count == count
            assert auth.extensions == {"thirdPartyPayment": payment, "credBlob": b"brainpool"}
            message, signature = response[2] + digest, response[3]
            r, s = utils.decode_dss_signature(signature)
            assert r > 0 and s > 0 and utils.encode_dss_signature(r, s) == signature
            client.verify_signature(data.public_key, message, signature)
            for changed in (message[:-1] + bytes([message[-1] ^ 1]), message + b"x"):
                try:
                    client.verify_signature(data.public_key, changed, signature)
                except InvalidSignature:
                    pass
                else:
                    raise AssertionError("tampered message accepted")
    native_types()
    print("OpenSSL verified 8 Brainpool registrations and 16 assertions; libfido2 rejected unsupported native types")


def hid(path):
    lib = native_types()
    declarations = {
        "fido_cbor_info_new": (C.c_void_p, []),
        "fido_cbor_info_free": (None, [C.POINTER(C.c_void_p)]),
        "fido_dev_get_cbor_info": (C.c_int, [C.c_void_p, C.c_void_p]),
        "fido_cbor_info_algorithm_count": (C.c_size_t, [C.c_void_p]),
        "fido_cbor_info_algorithm_cose": (C.c_int, [C.c_void_p, C.c_size_t]),
        "fido_cbor_info_algorithm_type": (C.c_char_p, [C.c_void_p, C.c_size_t]),
    }
    for name, (result, args) in declarations.items():
        getattr(lib, name).restype, getattr(lib, name).argtypes = result, args
    dev, info = allocation(lib.fido_dev_new), allocation(lib.fido_cbor_info_new)
    opened = False
    try:
        check(lib, lib.fido_dev_open(dev, os.fsencode(path)))
        opened = True
        check(lib, lib.fido_dev_get_cbor_info(dev, info))
        algorithms = [lib.fido_cbor_info_algorithm_cose(info, i) for i in range(lib.fido_cbor_info_algorithm_count(info))]
        assert algorithms == [a.identifier for a in client.ALGORITHMS]
        assert all(lib.fido_cbor_info_algorithm_type(info, i) == b"public-key" for i in range(len(algorithms)))
    finally:
        if opened:
            check(lib, lib.fido_dev_close(dev))
        lib.fido_cbor_info_free(C.byref(info))
        lib.fido_dev_free(C.byref(dev))
    print("libfido2 1.14 retained both advertised Brainpool IDs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fixtures")
    group.add_argument("--hid")
    args = parser.parse_args()
    (fixtures if args.fixtures else hid)(args.fixtures or args.hid)
