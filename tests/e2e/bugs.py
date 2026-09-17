"""The authenticator's known bugs, and the marker for tests they break.

See conftest.py for how a known_bug marker turns into a strict expected
failure.
"""

from __future__ import annotations

import re

import pytest
from fido2.ctap import CtapError


class KnownBugFailure(Exception):
    """A test failed in exactly the way its known_bug marker describes."""


def known_bug(reason: str, *, status: int | None = None, raises: type[BaseException] = CtapError, match: str | None = None):
    """Mark a test (or a pytest.param) as failing today because of a bug.

    `status` is the CTAP or CTAPHID status the failing request returns;
    `match` is a regular expression the exception message must match.
    """
    return pytest.mark.known_bug(reason=reason, status=status, raises=raises, match=match)


def describe(marker) -> str:
    kwargs = marker.kwargs
    expected = kwargs["raises"].__name__
    if kwargs["status"] is not None:
        expected += f" {kwargs['status']:#04x}"
    if kwargs["match"]:
        expected += f" matching {kwargs['match']!r}"
    return f"{kwargs['reason']} [expected failure: {expected}]"


def is_expected(marker, exc: BaseException) -> bool:
    kwargs = marker.kwargs
    if not isinstance(exc, kwargs["raises"]):
        return False
    if kwargs["status"] is not None and getattr(exc, "code", None) != kwargs["status"]:
        return False
    if kwargs["match"] and not re.search(kwargs["match"], str(exc)):
        return False
    return True


# Bug 1. The credential store is a single file written through Trussed, whose
# messages are capped at 1,024 bytes, so saving the credential list fails once
# it outgrows that. One ML-DSA-44 credential alone needs about 7.6 KB.
CREDENTIAL_STORE_CAPACITY = (
    "bug 1: the credential store is capped at 1,024 bytes, so saving the "
    "credential list fails with CTAP2_ERR_PROCESSING"
)

# Bug 2. clientPIN checks pinUvAuthParam as 16 bytes for both protocols, but
# protocol 2 sends the full 32-byte HMAC. Only the subcommands that carry a
# pinUvAuthParam are affected: getPinUvAuthTokenUsingPinWithPermissions has
# none, and makeCredential/getAssertion accept 32-byte parameters.
PIN_PROTOCOL_2_AUTH_PARAM = (
    "bug 2: setPIN and changePIN reject protocol 2's 32-byte pinUvAuthParam "
    "with CTAP2_ERR_PIN_AUTH_INVALID"
)
