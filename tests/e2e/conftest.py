"""Fixtures for the end-to-end tests of the virtual security key.

The tests talk to a running `pqkey attach` through its hidraw node,
named by the E2E_HIDRAW environment variable (see .github/workflows/e2e.yml):

    E2E_HIDRAW=/dev/hidrawN python -m pytest tests/e2e

Most tests use a key started with `--presence auto-approve` and the default
self attestation. Further instances are named by E2E_CERTIFICATE_HIDRAW
(`--presence auto-approve --attestation certificate`), for the attestation
certificate tests, and for the presence tests by E2E_NOTIFY_HIDRAW
(`--presence notify`, with DBUS_SESSION_BUS_ADDRESS naming a bus the tests'
fake notification server can own) and E2E_UNANSWERED_HIDRAW
(`--presence unanswered`).

They reset the authenticator (authenticatorReset) before each test, so they
must never be pointed at a security key whose credentials matter.

Known bugs
----------
A test of behaviour that is broken today carries `bugs.known_bug(...)`.
It is a strict expected failure that only counts the exact failure described
(the CTAP status, or the exception type and message), so:

* a test that starts passing fails the run (XPASS strict), so the marker is
  removed together with the fix;
* a test that fails differently from what the marker describes is reported as
  an ordinary failure rather than being hidden by the marker.
"""

from __future__ import annotations

import os
from typing import Iterator

import pytest
from fido2.ctap2 import Ctap2

import ctap as client
from bugs import KnownBugFailure, describe, is_expected


_OBSERVED = pytest.StashKey[str]()
_observed_failures: list[tuple[str, str]] = []


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "known_bug(reason, status, raises, match): strict expected failure for a documented bug",
    )


def pytest_collection_modifyitems(items):
    for item in items:
        marker = item.get_closest_marker("known_bug")
        if marker is not None:
            item.add_marker(pytest.mark.xfail(reason=describe(marker), raises=KnownBugFailure, strict=True))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    marker = item.get_closest_marker("known_bug")
    try:
        return (yield)
    except Exception as exc:
        if marker is not None and is_expected(marker, exc):
            item.stash[_OBSERVED] = f"{type(exc).__name__}: {exc}"
            raise KnownBugFailure(str(exc)) from exc
        raise


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    if call.when == "call" and hasattr(report, "wasxfail") and _OBSERVED in item.stash:
        _observed_failures.append((item.nodeid, item.stash[_OBSERVED]))
    return report


def pytest_terminal_summary(terminalreporter):
    if not _observed_failures:
        return
    terminalreporter.section("known bugs: observed failures")
    for nodeid, observed in _observed_failures:
        terminalreporter.write_line(f"{nodeid}\n    {observed}")


def _hidraw_from(variable: str, key: str) -> str:
    path = os.environ.get(variable)
    if not path:
        pytest.fail(f"{variable} must name the hidraw node of the {key}")
    return path


@pytest.fixture(scope="session")
def hidraw_path() -> str:
    """The key started with --presence auto-approve, used by most tests."""
    return _hidraw_from("E2E_HIDRAW", "virtual security key started with --presence auto-approve")


@pytest.fixture(scope="session")
def certificate_hidraw_path() -> str:
    """The key started with --presence auto-approve --attestation certificate."""
    return _hidraw_from(
        "E2E_CERTIFICATE_HIDRAW",
        "virtual security key started with --presence auto-approve --attestation certificate",
    )


@pytest.fixture(scope="session")
def notify_hidraw_path() -> str:
    """The key started with --presence notify, on the session bus of the tests."""
    return _hidraw_from("E2E_NOTIFY_HIDRAW", "virtual security key started with --presence notify")


@pytest.fixture(scope="session")
def unanswered_hidraw_path() -> str:
    """The key started with --presence unanswered, whose prompts wait until cancelled."""
    return _hidraw_from("E2E_UNANSWERED_HIDRAW", "virtual security key started with --presence unanswered")


@pytest.fixture
def device(hidraw_path):
    """A CTAPHID channel on the key, closed after the test.

    Every open hidraw descriptor receives every input report, so no other
    descriptor may stay open while a test reads raw packets.
    """
    dev = client.open_device(hidraw_path)
    try:
        yield dev
    finally:
        dev.close()


@pytest.fixture
def ctap(device) -> Ctap2:
    """A CTAP2 session on a freshly reset authenticator.

    authenticatorReset wipes all credentials and the PIN. Every test needs it:
    the credential store is shared by all credentials and currently fits a
    single ES256 credential.
    """
    session = Ctap2(device)
    session.reset()
    return session


@pytest.fixture
def certificate_ctap(certificate_hidraw_path) -> Iterator[Ctap2]:
    """A CTAP2 session on the freshly reset key with certificate attestation."""
    dev = client.open_device(certificate_hidraw_path)
    try:
        session = Ctap2(dev)
        session.reset()
        yield session
    finally:
        dev.close()
