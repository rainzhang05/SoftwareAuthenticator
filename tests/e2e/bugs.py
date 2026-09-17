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


# Bug 3. The CTAPHID layer answers CANCEL on an idle channel with an ERROR
# packet.
CTAPHID_CANCEL_WHILE_IDLE = "bug 3: CTAPHID answers CANCEL on an idle channel with ERROR 0x04 (invalid sequence)"
