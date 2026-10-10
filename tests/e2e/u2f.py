"""U2F polling for python-fido2, which sends each APDU only once."""

import time

from fido2.ctap1 import APDU, ApduError


def poll(operation, timeout=35.0):
    """Repeat an unchanged operation only when presence is required."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return operation()
        except ApduError as error:
            if error.code != APDU.USE_NOT_SATISFIED:
                raise
        if time.monotonic() >= deadline:
            raise TimeoutError("U2F presence approval timed out")
        time.sleep(0.1)
