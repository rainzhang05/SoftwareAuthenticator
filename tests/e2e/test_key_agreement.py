"""Raw classic COSE cases through python-fido2's actual HID device fixture.

Only public metadata/coordinates change after valid encapsulation. Collection
or use of an engine bridge is not evidence of real HID execution.
"""
import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2

import ctap as client
import persistent_management as persistent

PIN = "1234"
RP = "key-agreement.e2e.example"
PROTOCOLS = [PinProtocolV1, PinProtocolV2]
CONSUMERS = ["set", "change", "legacy", "transient", "persistent", "hmac", "hmac-mc"]


def mutate(original, case):
    key = dict(original)
    if case == 0:
        return key, True
    if case == 1:
        key[3] = -7
        return key, True
    if case == 2:
        key.update({2: b"kid", 99: False})
        return key, True
    if case < 15:
        label = [1, 3, -1][(case - 3) // 4]
        values = [None, True, "unexpected", {1: 1, 3: -26, -1: 2}[label]]
        value = values[(case - 3) % 4]
    elif case < 27:
        label = [-2, -3][(case - 15) // 6]
        value = [None, True, "unexpected", 0, bytes(31), bytes(33)][(case - 15) % 6]
    elif case == 27:
        key[-2] = key[-3] = bytes(32)
        return key, False
    else:
        label, value = 3, [0, -257, 2**63 - 1][case - 28]
    key.pop(label)
    if value is not None:
        key[label] = value
    return key, False


def pin_request(protocol, shared, agreement, consumer, wrong=False):
    sub = {"set": 3, "change": 4, "legacy": 5}.get(consumer, 9)
    fields = {1: protocol.VERSION, 2: sub, 3: agreement}
    message = b""
    if consumer in ("set", "change"):
        fields[5] = protocol.encrypt(shared, b"5678".ljust(64, b"\0"))
        message += fields[5]
    if consumer != "set":
        fields[6] = protocol.encrypt(shared, client.sha256(("wrong" if wrong else PIN).encode())[:16])
        message += fields[6]
    if consumer in ("set", "change"):
        fields[4] = protocol.authenticate(shared, message)
    if consumer in ("transient", "persistent"):
        fields[9] = 4 if consumer == "transient" else 0x40
    return fields


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=["protocol-1", "protocol-2"])
@pytest.mark.parametrize("consumer", CONSUMERS)
@pytest.mark.parametrize("case", range(31))
def test_required_key_agreement_metadata(ctap, protocol, consumer, case):
    protocol = protocol()
    # A stored credential permits checking that rejected HMAC operations neither
    # sign nor publish another credential. Create it before PIN protection.
    credential = client.register(ctap, RP, client.ES256, options={"rk": True}, extensions={"hmac-secret": True})
    previous = None
    if consumer == "hmac":
        previous, _ = client.authenticate(ctap, credential)
    pin = ClientPin(ctap, protocol)
    retained = []
    if consumer != "set":
        pin.set_pin(PIN)
        for selected in PROTOCOLS:
            selected = selected()
            retained.append((selected, persistent.obtain(ctap, selected, PIN)))
        writable = pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        count = persistent.manage(ctap, protocol, writable, 1)[1]
    agreement, shared = protocol.encapsulate(ctap.send_cbor(0x06, {1: protocol.VERSION, 2: 2})[1])
    agreement, accepted = mutate(agreement, case)
    retries = pin.get_pin_retries()
    for wrong in ([False, True] if not accepted and consumer in ("change", "legacy", "transient", "persistent") else [False]):
        def send():
            if consumer in ("hmac", "hmac-mc"):
                encrypted = protocol.encrypt(shared, bytes([0x98]) * 32)
                extension = {1: agreement, 2: encrypted, 3: protocol.authenticate(shared, encrypted), 4: protocol.VERSION}
                if consumer == "hmac":
                    return client.authenticate(ctap, credential, extensions={"hmac-secret": extension})[0]
                return client.register(ctap, RP, client.ES256, extensions={"hmac-secret": True, "hmac-secret-mc": extension})
            return ctap.send_cbor(0x06, pin_request(protocol, shared, agreement, consumer, wrong))
        if accepted:
            response = send()
            if consumer in ("legacy", "transient", "persistent"):
                assert len(response[2]) == (32 if protocol.VERSION == 1 else 48)
                assert len(protocol.decrypt(shared, response[2])) == 32
            elif consumer in ("hmac", "hmac-mc"):
                data = client.AuthData.parse(response[2]) if consumer == "hmac" else response.auth_data
                encrypted = data.extensions["hmac-secret" if consumer == "hmac" else "hmac-secret-mc"]
                assert len(encrypted) == (32 if protocol.VERSION == 1 else 48)
                assert len(protocol.decrypt(shared, encrypted)) == 32
        else:
            with pytest.raises(CtapError) as error:
                send()
            assert error.value.code == CtapError.ERR.INVALID_PARAMETER
            assert pin.get_pin_retries() == retries
    if not accepted and consumer != "set":
        for selected, token in retained:
            assert persistent.manage(ctap, selected, token, 1)[1] == count
        if consumer in ("hmac", "hmac-mc"):
            with pytest.raises(CtapError) as error:
                persistent.manage(ctap, protocol, writable, 1)
            assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID
        else:
            assert persistent.manage(ctap, protocol, writable, 1)[1] == count
        assert pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        if consumer == "hmac":
            after, _ = client.authenticate(ctap, credential)
            assert client.AuthData.parse(after[2]).sign_count == client.AuthData.parse(previous[2]).sign_count + 1
    elif not accepted:
        assert ctap.send_cbor(0x04)[4]["clientPin"] is False
