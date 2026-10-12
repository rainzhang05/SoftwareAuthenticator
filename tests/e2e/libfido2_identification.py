"""libfido2's forced-U2F touch API sends WINK before a separate presence request."""

import ctypes
import ctypes.util
import os
import sys

from notifications import FakeNotificationServer


def main():
    lib = ctypes.CDLL(ctypes.util.find_library("fido2"))
    lib.fido_init.argtypes = [ctypes.c_int]
    lib.fido_init.restype = None
    lib.fido_dev_new.argtypes = []
    lib.fido_dev_new.restype = ctypes.c_void_p
    lib.fido_dev_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.fido_dev_flags.argtypes = [ctypes.c_void_p]
    lib.fido_dev_flags.restype = ctypes.c_uint8
    lib.fido_dev_force_u2f.argtypes = [ctypes.c_void_p]
    lib.fido_dev_force_u2f.restype = None
    lib.fido_dev_get_touch_begin.argtypes = [ctypes.c_void_p]
    lib.fido_dev_get_touch_status.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
    lib.fido_dev_set_timeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.fido_dev_close.argtypes = [ctypes.c_void_p]
    lib.fido_dev_free.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.fido_dev_free.restype = None
    lib.fido_init(0)
    server = FakeNotificationServer().start()
    server.answer = None
    device = ctypes.c_void_p(lib.fido_dev_new())
    opened = False
    try:
        assert device
        assert lib.fido_dev_open(device, os.fsencode(sys.argv[1])) == 0
        opened = True
        assert lib.fido_dev_flags(device) & 1
        assert lib.fido_dev_set_timeout(device, 1500) == 0
        lib.fido_dev_force_u2f(device)
        assert lib.fido_dev_get_touch_begin(device) == 0
        identification = server.wait_for_shown()
        assert identification.summary == "Identify the security key"
        assert identification.actions == []
        assert identification.expire_timeout == 2000
        assert "pqkey-" in identification.body
        prompt = server.wait_for_shown(2)
        assert prompt.summary == "Register a security key"
        assert prompt.actions == ["approve", "Approve", "deny", "Deny"]
        # WINK did not supply the touch the separate MSG request needs.
        touched = ctypes.c_int(-1)
        assert lib.fido_dev_get_touch_status(device, ctypes.byref(touched), 150) == 0
        assert touched.value == 0
        server.answer_notification(prompt.id, "deny")
    finally:
        for shown in server.shown:
            if shown.actions:
                server.answer_notification(shown.id, "deny")
        if opened:
            lib.fido_dev_close(device)
        lib.fido_dev_free(ctypes.byref(device))
        server.stop()


if __name__ == "__main__":
    main()
