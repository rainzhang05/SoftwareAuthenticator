"""Direct 0x41 HID requests with legacy and modern tokens; no byte translation.

python-fido2 2.2.1 selects 0x0A when credMgmt is advertised, so these tests
explicitly send its CREDENTIAL_MGMT_PRE command and keep getInfo unmodified.
"""
import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CTAPHID

import ctap as client
from notifications import FakeNotificationServer
from test_credential_management import PIN, RP_A, RP_B, capacity, registered  # shared fixtures

PRE = Ctap2.CMD.CREDENTIAL_MGMT_PRE


@pytest.fixture
def identification_server():
    server = FakeNotificationServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(params=[PinProtocolV1, PinProtocolV2], ids=["protocol-1", "protocol-2"])
def protocol(request):
    return request.param()


@pytest.fixture(params=[True, False], ids=["legacy", "modern-cm"])
def grant(request, ctap, registered, protocol):
    pin = ClientPin(ctap, protocol)
    return pin.get_pin_token(PIN) if request.param else pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)


def request(protocol, token, sub, params=None):
    fields = {1: sub}
    if params is not None:
        fields[2] = params
    if sub not in (3, 5):
        message = bytes([sub])
        if sub not in (1, 2) and params is not None:
            message += cbor.encode(params)
        fields.update({3: protocol.VERSION, 4: protocol.authenticate(token, message)})
    return fields


def manage(ctap, protocol, token, sub, params=None, family=PRE):
    return ctap.send_cbor(family, request(protocol, token, sub, params))


def fails(code, action):
    with pytest.raises(CtapError) as error:
        action()
    assert error.value.code == code


def test_preview_advertisement_and_all_operations(ctap, registered, protocol, grant, capacity):
    assert "FIDO_2_1_PRE" in ctap.info.versions
    assert ctap.info.options["credMgmt"] and ctap.info.options["credentialMgmtPreview"]
    assert "userVerificationMgmtPreview" not in ctap.info.options
    assert "bioEnroll" not in ctap.info.options
    meta = manage(ctap, protocol, grant, 1)
    assert meta == {1: 3, 2: capacity - 3}
    first = manage(ctap, protocol, grant, 2)
    second = manage(ctap, protocol, grant, 3)
    assert first[5] == 2 and 5 not in second
    assert {first[4], second[4]} == {client.sha256(r.encode()) for r in (RP_A, RP_B)}
    first = manage(ctap, protocol, grant, 4, {1: client.sha256(RP_A.encode())})
    second = manage(ctap, protocol, grant, 5)
    assert first[9] == 2 and 9 not in second
    entries = {entry[7]["id"]: entry for entry in (first, second)}
    for name in ("alice", "bob"):
        credential, user = registered[name]
        entry = entries[credential.credential_id]
        assert entry[6] == user and entry[8] == credential.public_key
        assert entry[10] == (2 if name == "bob" else 1)
        assert entry[12] is False
    credential, user = registered["alice"]
    params = {2: {"type": "public-key", "id": credential.credential_id}, 3: {"id": user["id"], "name": "Updated"}}
    assert manage(ctap, protocol, grant, 7, params) == {}
    updated = manage(ctap, protocol, grant, 4, {1: client.sha256(RP_A.encode())})
    if updated[7]["id"] != credential.credential_id:
        updated = manage(ctap, protocol, grant, 5)
    assert updated[6] == {"id": user["id"], "name": "Updated"}
    assert updated[8] == credential.public_key
    assert manage(ctap, protocol, grant, 6, {2: params[2]}) == {}
    assert manage(ctap, protocol, grant, 1)[1] == 2
    fails(CtapError.ERR.NO_CREDENTIALS, lambda: client.authenticate(ctap, credential))
    client.authenticate(ctap, registered["bob"][0])


def test_legacy_grant_is_not_standard_cm_authorization(ctap, registered, protocol):
    token = ClientPin(ctap, protocol).get_pin_token(PIN)
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, token, 1, family=Ctap2.CMD.CREDENTIAL_MGMT))
    assert manage(ctap, protocol, token, 1)[1] == 3


@pytest.mark.parametrize("permission", [1, 2, 3, 0x10, 0x20, 0x30])
def test_modern_non_cm_grants_do_not_authorize_preview(ctap, registered, protocol, permission):
    token = ClientPin(ctap, protocol).get_pin_token(PIN, permission, RP_A if permission & 3 else None)
    for sub, params in [(1, None), (4, {1: client.sha256(RP_A.encode())}), (6, {2: {"type": "public-key", "id": registered["alice"][0].credential_id}})]:
        fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, token, sub, params))
    client.authenticate(ctap, registered["bob"][0])


def test_preview_scope_restrictions(ctap, registered, protocol):
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT, RP_A)
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, token, 2))
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, token, 4, {1: client.sha256(RP_B.encode())}))
    assert manage(ctap, protocol, token, 4, {1: client.sha256(RP_A.encode())})[9] == 2
    assert manage(ctap, protocol, token, 5)[7]["id"] in {registered[n][0].credential_id for n in ("alice", "bob")}


@pytest.mark.parametrize("first,second", [(0x0A, 0x41), (0x41, 0x0A)])
def test_family_switch_discards_both_independent_cursors(ctap, registered, protocol, first, second):
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    manage(ctap, protocol, token, 2, family=first)
    manage(ctap, protocol, token, 4, {1: client.sha256(RP_A.encode())}, family=first)
    fails(CtapError.ERR.NOT_ALLOWED, lambda: manage(ctap, protocol, token, 5, family=second))
    for sub in (3, 5):
        fails(CtapError.ERR.NOT_ALLOWED, lambda: manage(ctap, protocol, token, sub, family=first))


def test_wink_and_lock_preserve_preview_cursors(ctap, registered, protocol, grant, identification_server):
    manage(ctap, protocol, grant, 2)
    manage(ctap, protocol, grant, 4, {1: client.sha256(RP_A.encode())})
    ctap.device.call(CTAPHID.LOCK, b"\x01")
    try:
        ctap.device.wink()
        assert identification_server.wait_for_shown().actions == []
        assert manage(ctap, protocol, grant, 3)[4] == client.sha256(RP_B.encode())
        assert manage(ctap, protocol, grant, 5)[7]["id"] in {registered[n][0].credential_id for n in ("alice", "bob")}
    finally:
        ctap.device.call(CTAPHID.LOCK, b"\x00")


def test_missing_malformed_and_wrong_macs_keep_retries_and_credentials(ctap, registered, protocol, grant):
    pin = ClientPin(ctap, protocol)
    before = pin.get_pin_retries()
    valid = request(protocol, grant, 1)
    for fields, code in [
        ({1: 1}, CtapError.ERR.PUAT_REQUIRED),
        ({1: 1, 4: valid[4]}, CtapError.ERR.MISSING_PARAMETER),
        ({1: 1, 3: 3, 4: valid[4]}, CtapError.ERR.INVALID_PARAMETER),
        ({1: 1, 3: True, 4: valid[4]}, CtapError.ERR.CBOR_UNEXPECTED_TYPE),
        ({1: 1, 3: protocol.VERSION, 4: True}, CtapError.ERR.CBOR_UNEXPECTED_TYPE),
        ({1: 1, 3: protocol.VERSION, 4: b""}, CtapError.ERR.PIN_AUTH_INVALID),
        ({1: 1, 3: protocol.VERSION, 4: b"x" * 17}, CtapError.ERR.PIN_AUTH_INVALID),
    ]:
        fails(code, lambda: ctap.send_cbor(PRE, fields))
    for _ in range(4):
        fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, b"x" * 32, 1))
    assert pin.get_pin_retries() == before
    assert manage(ctap, protocol, grant, 1)[1] == 3
    replacement = pin.get_pin_token(PIN)
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, grant, 1))
    assert manage(ctap, protocol, replacement, 1)[1] == 3
    pin.change_pin(PIN, "5678")
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, replacement, 1))
    client.authenticate(ctap, registered["bob"][0])
