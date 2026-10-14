"""Raw persistent ClientPIN requests; no dependency on a pcmr enum or cache."""
import hmac
from fido2.ctap2 import Ctap2
import ctap as client


def obtain(ctap, protocol, pin, permissions=0x40, rp_id=None):
    agreement, shared = protocol.encapsulate(ctap.send_cbor(0x06, {1: protocol.VERSION, 2: 2})[1])
    fields = {1: protocol.VERSION, 2: 9, 3: agreement,
              6: protocol.encrypt(shared, client.sha256(pin.encode())[:16]), 9: permissions}
    if rp_id is not None:
        fields[10] = rp_id
    encrypted = ctap.send_cbor(0x06, fields)[2]
    assert len(encrypted) == (32 if protocol.VERSION == 1 else 48)
    secret = protocol.decrypt(shared, encrypted)
    assert len(secret) == 32
    return secret


def same(first, second):
    if not hmac.compare_digest(first, second):
        raise AssertionError("persistent secret changed without rotation")


def manage(ctap, protocol, secret, sub, params=None, family=0x0a):
    from fido2 import cbor
    fields = {1: sub}
    if params is not None:
        fields[2] = params
    if sub not in (3, 5):
        message = bytes([sub])
        if sub not in (1, 2) and params is not None:
            message += cbor.encode(params)
        auth = protocol.authenticate(secret, message)
        assert len(auth) == (16 if protocol.VERSION == 1 else 32)
        fields.update({3: protocol.VERSION, 4: auth})
    return ctap.send_cbor(family, fields)
