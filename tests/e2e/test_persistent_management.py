"""CTAP 2.3 persistent management over actual HID, both PIN protocols."""
import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CTAPHID
import ctap as client
from persistent_management import obtain, manage, same
from notifications import FakeNotificationServer

PIN = "1234"

@pytest.fixture(params=[PinProtocolV1, PinProtocolV2], ids=["protocol-1", "protocol-2"])
def protocol(request):
    return request.param()


def fails(code, action):
    with pytest.raises(CtapError) as error:
        action()
    assert error.value.code == code


def test_permission_negotiation_empty_store_and_protocol_independence(ctap, protocol):
    assert ctap.info.options["perCredMgmtRO"] is True
    pin = ClientPin(ctap, protocol)
    pin.set_pin(PIN)
    for permission in (1, 2, 4, 8, 0x10, 0x20):
        fails(CtapError.ERR.UNAUTHORIZED_PERMISSION, lambda: obtain(ctap, protocol, PIN, 0x40 | permission))
    secret = obtain(ctap, protocol, PIN)
    for permissions in (0x40, 0xc0, 0xffffffffffffffc0):
        same(secret, obtain(ctap, protocol, PIN, permissions, "ignored.example"))
    assert manage(ctap, protocol, secret, 1)[1] == 0
    fails(CtapError.ERR.NO_CREDENTIALS, lambda: manage(ctap, protocol, secret, 2))
    fails(CtapError.ERR.NO_CREDENTIALS, lambda: manage(ctap, protocol, secret, 4, {1: client.sha256(b"none.example")}))
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, secret, 1, family=0x41))
    other = PinProtocolV2() if protocol.VERSION == 1 else PinProtocolV1()
    other_secret = obtain(ctap, other, PIN)
    same(secret, obtain(ctap, protocol, PIN))
    assert manage(ctap, other, other_secret, 1)[1] == 0
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, other, secret, 1))
    fails(CtapError.ERR.PIN_INVALID, lambda: obtain(ctap, protocol, "9999"))
    assert manage(ctap, protocol, secret, 1)[1] == 0
    pin.get_pin_token(PIN)  # Legacy issuance is transient, and does not rotate pcmr.
    assert manage(ctap, protocol, secret, 1)[1] == 0
    pin.change_pin(PIN, "5678")
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, secret, 1))


def test_reads_mutations_and_wink_lock_cursor_preservation(ctap, protocol):
    registered = [(client.register(ctap, rp, client.ES256, user=client.user_entity(name), options={"rk": True}), rp)
                  for rp, name in [("a.pcmr.example", "alice"), ("a.pcmr.example", "bob"), ("b.pcmr.example", "carol")]]
    ClientPin(ctap, protocol).set_pin(PIN)
    secret = obtain(ctap, protocol, PIN)
    assert manage(ctap, protocol, secret, 1)[1] == 3
    assert manage(ctap, protocol, secret, 2)[5] == 2
    assert manage(ctap, protocol, secret, 4, {1: client.sha256(b"a.pcmr.example")})[9] == 2
    server = FakeNotificationServer().start()
    try:
        ctap.device.call(CTAPHID.LOCK, b"\x01")
        ctap.device.wink()
        assert server.wait_for_shown().actions == []
        assert 3 in manage(ctap, protocol, secret, 3)
        assert 7 in manage(ctap, protocol, secret, 5)
    finally:
        ctap.device.call(CTAPHID.LOCK, b"\x00")
        server.stop()
    descriptor = {"type": "public-key", "id": registered[0][0].credential_id}
    for sub, params in ((6, {2: descriptor}), (7, {2: descriptor, 3: {"id": b"invalid"}})):
        fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, secret, sub, params))
    manage(ctap, protocol, secret, 2)
    ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    fails(CtapError.ERR.NOT_ALLOWED, lambda: manage(ctap, protocol, secret, 3))
    assert manage(ctap, protocol, secret, 1)[1] == 3

@pytest.mark.parametrize("policy", [{1: 6}, {4: True}], ids=["minimum", "complexity"])
def test_persistent_rotation_on_forced_policy_and_reset(ctap, protocol, policy):
    from fido2 import cbor
    import hmac
    pin = ClientPin(ctap, protocol)
    pin.set_pin(PIN)
    secret = obtain(ctap, protocol, PIN)
    writable = pin.get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    message = b"\xff" * 32 + b"\x0d\x03" + cbor.encode(policy)
    ctap.send_cbor(0x0d, {1: 3, 2: policy, 3: protocol.VERSION, 4: protocol.authenticate(writable, message)})
    fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, secret, 1))
    fails(CtapError.ERR.PIN_POLICY_VIOLATION, lambda: obtain(ctap, protocol, PIN))
    pin.change_pin(PIN, "Ab123456")
    replacement = obtain(ctap, protocol, "Ab123456")
    if hmac.compare_digest(secret, replacement):
        raise AssertionError("policy/PIN rotation reused a persistent secret")
    assert manage(ctap, protocol, replacement, 1)[1] == 0
    ctap.reset()
    for revoked in (secret, replacement):
        fails(CtapError.ERR.PIN_AUTH_INVALID, lambda: manage(ctap, protocol, revoked, 1))
