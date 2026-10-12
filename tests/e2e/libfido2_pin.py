"""Exercise libfido2 PIN APIs against the disposable auto-approve HID key.

Uses only the Python standard library and libfido2 installed for fido2-tools.
The pqkey CLI enables the policy, which libfido2 1.14 cannot configure.
"""

import ctypes
import ctypes.util
import os
from pathlib import Path
import subprocess
import sys


def main():
    library = ctypes.util.find_library("fido2")
    if library is None:
        raise RuntimeError("libfido2 is required")
    lib = ctypes.CDLL(library)
    lib.fido_init.argtypes = [ctypes.c_int]
    lib.fido_init.restype = None
    lib.fido_dev_new.argtypes = []
    lib.fido_dev_new.restype = ctypes.c_void_p
    lib.fido_dev_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.fido_dev_open.restype = ctypes.c_int
    lib.fido_dev_close.argtypes = [ctypes.c_void_p]
    lib.fido_dev_close.restype = ctypes.c_int
    lib.fido_dev_free.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.fido_dev_free.restype = None
    lib.fido_dev_set_pin.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.fido_dev_set_pin.restype = ctypes.c_int
    lib.fido_strerr.argtypes = [ctypes.c_int]
    lib.fido_strerr.restype = ctypes.c_char_p
    lib.fido_init(0)

    def check(code, expected="FIDO_OK"):
        actual = lib.fido_strerr(code).decode("ascii")
        if actual != expected:
            raise AssertionError(f"libfido2 returned {actual}; expected {expected}")

    def pins(cases):
        device = ctypes.c_void_p(lib.fido_dev_new())
        if not device:
            raise RuntimeError("fido_dev_new failed")
        opened = False
        try:
            check(lib.fido_dev_open(device, os.fsencode(sys.argv[1])))
            opened = True
            for new, old, expected in cases:
                check(lib.fido_dev_set_pin(device, new.encode("utf-8"), old.encode("utf-8") if old else None), expected)
        finally:
            if opened:
                lib.fido_dev_close(device)
            lib.fido_dev_free(ctypes.byref(device))

    pins([("1234", None, "FIDO_OK"), ("5678", "1234", "FIDO_OK")])
    result = subprocess.run([
        os.environ.get("PQKEY", "target/release/pqkey"), "config", "pin-complexity", "--yes",
        "--state-dir", str(Path(sys.argv[2])),
    ], input="5678\n", text=True, capture_output=True, timeout=40, check=True)
    assert "PIN complexity: on." in result.stdout
    pins([
        ("9999", "5678", "FIDO_ERR_PIN_POLICY_VIOLATION"),
        ("abcd", "5678", "FIDO_ERR_PIN_POLICY_VIOLATION"),
        ("Ab12", "5678", "FIDO_OK"),
        ("éA23", "Ab12", "FIDO_OK"),
    ])


if __name__ == "__main__":
    main()
