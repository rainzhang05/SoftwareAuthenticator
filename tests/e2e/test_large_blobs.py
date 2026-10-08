"""Large-blob arrays and credential keys through python-fido2 2.2.1.

LargeBlobs exercises the platform's fragmentation, compression and encryption.
Raw requests cover inputs its helpers never send. The ctap fixture resets the
key before every test, including every parameterized case.
"""

import os
import struct

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.config import Config
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CTAPHID

import ctap as client

RP_ID = "large-blobs.e2e.example"
PIN = "4821"
INITIAL = bytes.fromhex("8076be8b528d0075f7aae98d6fa57a6d3c")
CAPACITY = 16_384
FRAGMENT = 1704
ERR = CtapError.ERR
RESULT = CredentialManagement.RESULT


@pytest.fixture(params=[
    pytest.param(PinProtocolV1, id="protocol-1"),
    pytest.param(PinProtocolV2, id="protocol-2"),
])
def protocol(request):
    return request.param()


def _serialized(array) -> bytes:
    data = cbor.encode(array)
    return data + client.sha256(data)[:16]


def _read(ctap: Ctap2) -> bytes:
    result = b""
    while True:
        fragment = ctap.large_blobs(len(result), get=FRAGMENT)[1]
        result += fragment
        if len(fragment) < FRAGMENT:
            assert result[-16:] == client.sha256(result[:-16])[:16]
            return result


def _error(ctap: Ctap2, parameters: dict, expected):
    with pytest.raises(CtapError) as error:
        ctap.send_cbor(Ctap2.CMD.LARGE_BLOBS, parameters)
    assert error.value.code == expected


def _auth(protocol, token: bytes, offset: int, fragment: bytes) -> dict:
    message = (
        b"\xff" * 32 + b"\x0c\x00" + struct.pack("<I", offset)
        + client.sha256(fragment)
    )
    return {5: protocol.authenticate(token, message), 6: protocol.VERSION}


def test_initial_array_and_fragmented_platform_roundtrip(ctap):
    blobs = LargeBlobs(ctap)
    assert blobs.max_fragment_length == FRAGMENT
    assert blobs.read_blob_array() == []
    assert _read(ctap) == INITIAL
    array = [{1: os.urandom(4096), 2: os.urandom(12), 3: 4080}]
    serialized = _serialized(array)
    assert len(serialized) > FRAGMENT * 2
    blobs.write_blob_array(array)
    assert blobs.read_blob_array() == array
    assert _read(ctap) == serialized
    ctap.reset()
    assert _read(ctap) == INITIAL


def test_platform_put_get_replace_and_delete_encrypted_blobs(ctap):
    first = client.register(
        ctap, RP_ID, client.ES256, options={"rk": True},
        extensions={"largeBlobKey": True},
    )
    second = client.register(
        ctap, RP_ID, client.ES256, options={"rk": True},
        extensions={"largeBlobKey": True},
    )
    assert len(first.large_blob_key) == len(second.large_blob_key) == 32
    assert first.large_blob_key != second.large_blob_key
    blobs = LargeBlobs(ctap)
    data = os.urandom(8192)
    blobs.put_blob(first.large_blob_key, data)
    assert len(_read(ctap)) > FRAGMENT
    assert blobs.get_blob(first.large_blob_key) == data
    assert blobs.get_blob(second.large_blob_key) is None
    blobs.put_blob(second.large_blob_key, b"second credential")
    blobs.put_blob(first.large_blob_key, b"replacement")
    assert len(blobs.read_blob_array()) == 2
    assert blobs.get_blob(first.large_blob_key) == b"replacement"
    assert blobs.get_blob(second.large_blob_key) == b"second credential"
    blobs.delete_blob(first.large_blob_key)
    assert blobs.get_blob(first.large_blob_key) is None
    assert blobs.get_blob(second.large_blob_key) == b"second credential"
    blobs.delete_blob(second.large_blob_key)
    assert blobs.read_blob_array() == []
    assert _read(ctap) == INITIAL


@pytest.mark.parametrize("parameters,expected", [
    ({1: 1}, ERR.INVALID_PARAMETER),
    ({3: 0}, ERR.INVALID_PARAMETER),
    ({1: 1, 2: b"", 3: 0}, ERR.INVALID_PARAMETER),
    ({1: 1, 3: 0, 4: 17}, ERR.INVALID_PARAMETER),
    ({1: 1, 3: 0, 5: b""}, ERR.INVALID_PARAMETER),
    ({1: 1, 3: 0, 6: 1}, ERR.INVALID_PARAMETER),
    ({1: FRAGMENT + 1, 3: 0}, ERR.INVALID_LENGTH),
    ({1: 1, 3: len(INITIAL) + 1}, ERR.INVALID_PARAMETER),
    ({2: b"", 4: 17}, ERR.INVALID_PARAMETER),
    ({2: b"", 3: 0}, ERR.INVALID_PARAMETER),
    ({2: b"", 3: 0, 4: 16}, ERR.INVALID_PARAMETER),
    ({2: b"", 3: 0, 4: CAPACITY + 1}, ERR.LARGE_BLOB_STORAGE_FULL),
    ({2: b"x" * (FRAGMENT + 1), 3: 0, 4: FRAGMENT + 1}, ERR.INVALID_LENGTH),
    ({2: b"x", 3: 1, 4: 17}, ERR.INVALID_PARAMETER),
    ({2: b"x", 3: 1}, ERR.INVALID_SEQ),
    ({2: b"x" * 18, 3: 0, 4: 17}, ERR.INVALID_PARAMETER),
    ({2: b"x" * 17, 3: 0, 4: 17}, ERR.INTEGRITY_FAILURE),
    # Earlier checks win when the request breaks several rules.
    ({1: FRAGMENT + 1, 3: 99, 4: 17}, ERR.INVALID_PARAMETER),
    ({2: b"x" * (FRAGMENT + 1), 3: 0}, ERR.INVALID_LENGTH),
])
def test_raw_read_and_write_errors_leave_the_committed_array(ctap, parameters, expected):
    _error(ctap, parameters, expected)
    assert _read(ctap) == INITIAL


def test_read_substrings_and_empty_results(ctap):
    assert ctap.large_blobs(0, get=0) == {1: b""}
    assert ctap.large_blobs(3, get=4) == {1: INITIAL[3:7]}
    assert ctap.large_blobs(10, get=FRAGMENT) == {1: INITIAL[10:]}
    assert ctap.large_blobs(len(INITIAL), get=FRAGMENT) == {1: b""}


@pytest.mark.parametrize("parameters", [
    {1: "1", 3: 0}, {1: True, 3: 0}, {2: "bytes", 3: 0, 4: 17},
    {1: 1, 3: "0"}, {2: b"", 3: 0, 4: "17"},
])
def test_raw_requests_reject_wrong_types(ctap, parameters):
    _error(ctap, parameters, ERR.CBOR_UNEXPECTED_TYPE)


@pytest.mark.parametrize("payload", [
    b"", b"\xa1\x01", b"\x80", b"\xa2\x03\x00\x03\x01",
])
def test_raw_requests_reject_malformed_cbor(ctap, payload):
    assert ctap.device.call(
        CTAPHID.CBOR, bytes([Ctap2.CMD.LARGE_BLOBS]) + payload
    ) == bytes([ERR.INVALID_CBOR])


def test_exact_maximum_fragment_and_capacity(ctap):
    data = os.urandom(CAPACITY - 16)
    serialized = data + client.sha256(data)[:16]
    # The authenticator checks only the trailing hash, not the opaque body.
    assert ctap.large_blobs(0, set=serialized[:FRAGMENT], length=CAPACITY) == {}
    for offset in range(FRAGMENT, CAPACITY, FRAGMENT):
        assert ctap.large_blobs(offset, set=serialized[offset:offset + FRAGMENT]) == {}
    assert _read(ctap) == serialized


def test_continuation_length_sequence_bounds_and_hash(ctap):
    serialized = _serialized([{1: os.urandom(2048), 2: os.urandom(12), 3: 2032}])
    ctap.large_blobs(0, set=serialized[:FRAGMENT], length=len(serialized))
    _error(ctap, {2: serialized[FRAGMENT:], 3: FRAGMENT, 4: len(serialized)}, ERR.INVALID_PARAMETER)
    # Start again after each rejected continuation; malformed requests may
    # abandon state under §6's stateful-command accommodations.
    ctap.large_blobs(0, set=serialized[:FRAGMENT], length=len(serialized))
    _error(ctap, {2: b"x", 3: FRAGMENT + 1}, ERR.INVALID_SEQ)
    ctap.large_blobs(0, set=serialized[:FRAGMENT], length=len(serialized))
    _error(ctap, {2: serialized[FRAGMENT:] + b"x", 3: FRAGMENT}, ERR.INVALID_PARAMETER)
    ctap.large_blobs(0, set=serialized[:FRAGMENT], length=len(serialized))
    bad = serialized[FRAGMENT:-1] + bytes([serialized[-1] ^ 1])
    _error(ctap, {2: bad, 3: FRAGMENT}, ERR.INTEGRITY_FAILURE)
    _error(ctap, {2: serialized[FRAGMENT:], 3: FRAGMENT}, ERR.INVALID_SEQ)
    assert _read(ctap) == INITIAL


@pytest.mark.parametrize("intervening", ["get", "getInfo", "malformed"])
def test_intervening_request_drops_an_incomplete_write(ctap, intervening):
    serialized = _serialized([{1: os.urandom(2048), 2: os.urandom(12), 3: 2032}])
    ctap.large_blobs(0, set=serialized[:FRAGMENT], length=len(serialized))
    if intervening == "get":
        assert _read(ctap) == INITIAL
    elif intervening == "getInfo":
        ctap.get_info()
    else:
        assert ctap.device.call(CTAPHID.CBOR, b"\x0c\xa1") == bytes([ERR.INVALID_CBOR])
    _error(ctap, {2: serialized[FRAGMENT:], 3: FRAGMENT}, ERR.INVALID_SEQ)
    assert _read(ctap) == INITIAL


def test_pin_authorizes_platform_writes_with_lbw(ctap, protocol):
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    with pytest.raises(CtapError) as error:
        LargeBlobs(ctap).write_blob_array([])
    assert error.value.code == ERR.PUAT_REQUIRED
    token = ClientPin(ctap, protocol).get_pin_token(
        PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE, RP_ID
    )
    blobs = LargeBlobs(ctap, protocol, token)
    array = [{1: os.urandom(4096), 2: os.urandom(12), 3: 4080}]
    blobs.write_blob_array(array)
    assert blobs.read_blob_array() == array
    key = os.urandom(32)
    value = os.urandom(4096)
    blobs.put_blob(key, value)
    assert blobs.get_blob(key) == value
    blobs.delete_blob(key)
    assert blobs.read_blob_array() == array


def test_no_pin_ignores_write_authentication_parameters(ctap):
    assert ctap.send_cbor(Ctap2.CMD.LARGE_BLOBS, {
        2: INITIAL, 3: 0, 4: len(INITIAL), 5: b"wrong", 6: 99,
    }) == {}
    assert _read(ctap) == INITIAL


def test_pin_authentication_errors_and_permission_checks(ctap, protocol):
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    base = {2: INITIAL, 3: 0, 4: len(INITIAL)}
    for extra, expected in (
        ({6: 99}, ERR.PUAT_REQUIRED),
        ({5: b""}, ERR.MISSING_PARAMETER),
        ({5: b"", 6: 99}, ERR.INVALID_PARAMETER),
        ({5: b"wrong", 6: protocol.VERSION}, ERR.PIN_AUTH_INVALID),
    ):
        _error(ctap, {**base, **extra}, expected)
    token = ClientPin(ctap, protocol).get_pin_token(
        PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT
    )
    _error(ctap, {**base, **_auth(protocol, token, 0, INITIAL)}, ERR.PIN_AUTH_INVALID)
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
    _error(ctap, {**base, **_auth(protocol, os.urandom(32), 0, INITIAL)}, ERR.PIN_AUTH_INVALID)
    assert ctap.send_cbor(
        Ctap2.CMD.LARGE_BLOBS, {**base, **_auth(protocol, token, 0, INITIAL)}
    ) == {}


def test_always_uv_requires_authentication_even_without_a_pin(ctap):
    Config(ctap).toggle_always_uv()
    assert _read(ctap) == INITIAL
    _error(ctap, {2: INITIAL, 3: 0, 4: len(INITIAL)}, ERR.PUAT_REQUIRED)


def test_always_uv_accepts_lbw_tokens(ctap, protocol):
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    Config(ctap, protocol, token).toggle_always_uv()
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
    blobs = LargeBlobs(ctap, protocol, token)
    blobs.write_blob_array([{1: b"opaque", 2: os.urandom(12), 3: 0}])
    assert len(blobs.read_blob_array()) == 1


def test_lbw_permission_survives_assertion_user_presence(ctap, protocol):
    credential = client.register(ctap, RP_ID, client.ES256)
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    token = ClientPin(ctap, protocol).get_pin_token(
        PIN, ClientPin.PERMISSION.GET_ASSERTION | ClientPin.PERMISSION.LARGE_BLOB_WRITE, RP_ID
    )
    digest = os.urandom(32)
    client.authenticate(
        ctap, credential, uv=True, client_data_hash=digest,
        pin_uv_param=protocol.authenticate(token, digest), pin_uv_protocol=protocol.VERSION,
    )
    LargeBlobs(ctap, protocol, token).write_blob_array([])
    assert _read(ctap) == INITIAL


def test_replacing_the_token_drops_an_authenticated_write(ctap, protocol):
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    pin = ClientPin(ctap, protocol)
    token = pin.get_pin_token(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
    serialized = _serialized([{1: os.urandom(2048), 2: os.urandom(12), 3: 2032}])
    ctap.send_cbor(Ctap2.CMD.LARGE_BLOBS, {
        2: serialized[:FRAGMENT], 3: 0, 4: len(serialized),
        **_auth(protocol, token, 0, serialized[:FRAGMENT]),
    })
    replacement = pin.get_pin_token(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
    _error(ctap, {
        2: serialized[FRAGMENT:], 3: FRAGMENT,
        **_auth(protocol, replacement, FRAGMENT, serialized[FRAGMENT:]),
    }, ERR.INVALID_SEQ)
    assert _read(ctap) == INITIAL


@pytest.mark.parametrize("value", [False, 0, 1, "true", b"true", [], {}])
def test_large_blob_key_rejects_every_value_other_than_true(ctap, value):
    with pytest.raises(CtapError) as error:
        client.register(
            ctap, RP_ID, client.ES256, options={"rk": True},
            extensions={"largeBlobKey": value},
        )
    assert error.value.code == ERR.INVALID_OPTION
    credential = client.register(ctap, RP_ID, client.ES256, options={"rk": True})
    with pytest.raises(CtapError) as error:
        client.authenticate(ctap, credential, extensions={"largeBlobKey": value})
    assert error.value.code == ERR.INVALID_OPTION


@pytest.mark.parametrize("options", [None, {"rk": False}])
@pytest.mark.parametrize("alg", [client.ES256, client.RS256])
def test_large_blob_key_requires_a_discoverable_credential(ctap, options, alg):
    with pytest.raises(CtapError) as error:
        client.register(ctap, RP_ID, alg, options=options, extensions={"largeBlobKey": True})
    assert error.value.code == ERR.INVALID_OPTION


def test_large_blob_key_is_outer_response_data_and_is_requested_only(ctap):
    keyed = client.register(
        ctap, RP_ID, client.ES256, options={"rk": True},
        extensions={"largeBlobKey": True},
    )
    assert len(keyed.large_blob_key) == 32
    assert keyed.auth_data.extensions is None
    assert not keyed.auth_data.flags & client.FLAG_ED
    plain = client.register(ctap, RP_ID, client.ES256, options={"rk": True})
    sealed = client.register(ctap, RP_ID, client.ES256, options={"rk": False})
    rsa = client.register(ctap, RP_ID, client.RS256, options={"rk": False})
    assert plain.large_blob_key is None
    assert sealed.large_blob_key is None
    assert rsa.large_blob_key is None
    for credential in (keyed, plain, sealed, rsa):
        for requested in (False, True):
            response, data = client.authenticate(
                ctap, credential, extensions={"largeBlobKey": True} if requested else None
            )
            assert data.extensions is None
            assert not data.flags & client.FLAG_ED
            if requested and credential is keyed:
                assert response[7] == keyed.large_blob_key
            else:
                assert 7 not in response


def test_native_response_classes_return_the_same_key_with_pin_uv(ctap, protocol):
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    pin = ClientPin(ctap, protocol)
    token = pin.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP_ID)
    digest = os.urandom(32)
    registration = ctap.make_credential(
        digest, {"id": RP_ID, "name": RP_ID}, client.user_entity("native"),
        [{"type": "public-key", "alg": client.ES256}],
        extensions={"largeBlobKey": True, "credBlob": b"signed blob"},
        options={"rk": True}, pin_uv_param=protocol.authenticate(token, digest),
        pin_uv_protocol=protocol.VERSION,
    )
    key = registration.large_blob_key
    assert isinstance(key, bytes) and len(key) == 32
    data = client.AuthData.parse(registration.auth_data)
    data.check(RP_ID, up=True, uv=True, at=True)
    assert data.extensions == {"credBlob": True}
    client.verify_attestation(
        {1: registration.fmt, 2: registration.auth_data, 3: registration.att_stmt},
        data.public_key, digest,
    )
    token = pin.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, RP_ID)
    digest = os.urandom(32)
    assertion = ctap.get_assertion(
        RP_ID, digest, [{"type": "public-key", "id": data.credential_id}],
        extensions={"largeBlobKey": True, "credBlob": True},
        pin_uv_param=protocol.authenticate(token, digest), pin_uv_protocol=protocol.VERSION,
    )
    assert assertion.large_blob_key == key
    auth_data = client.AuthData.parse(assertion.auth_data)
    auth_data.check(RP_ID, up=True, uv=True, at=False)
    assert auth_data.extensions == {"credBlob": b"signed blob"}
    client.verify_signature(data.public_key, assertion.auth_data + digest, assertion.signature)


@pytest.mark.parametrize("requested", [False, True])
def test_get_next_assertion_keeps_the_key_request_for_each_credential(ctap, requested):
    keyed = client.register(
        ctap, RP_ID, client.ES256, options={"rk": True},
        extensions={"largeBlobKey": True},
    )
    plain = client.register(ctap, RP_ID, client.ES256, options={"rk": True})
    credentials = {credential.credential_id: credential for credential in (keyed, plain)}
    digest = os.urandom(32)
    first = client.get_assertion(
        ctap, RP_ID, digest, extensions={"largeBlobKey": True} if requested else None
    )
    assert first[5] == 2
    second = client.get_next_assertion(ctap)
    assert {first[1]["id"], second[1]["id"]} == set(credentials)
    for response in (first, second):
        credential = credentials[response[1]["id"]]
        assert response.get(7) == (credential.large_blob_key if requested else None)
        assert client.AuthData.parse(response[2]).extensions is None
        client.verify_signature(credential.public_key, response[2] + digest, response[3])


def test_credential_management_returns_keys_and_leaves_orphaned_blobs(ctap, protocol):
    user = client.user_entity("alice")
    keyed = client.register(
        ctap, RP_ID, client.ES256, user=user, options={"rk": True},
        extensions={"largeBlobKey": True},
    )
    plain = client.register(ctap, RP_ID, client.ES256, options={"rk": True})
    LargeBlobs(ctap).put_blob(keyed.large_blob_key, b"retained after deletion")
    before = _read(ctap)
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    management = CredentialManagement(ctap, protocol, token)
    first = management.enumerate_creds_begin(client.sha256(RP_ID.encode()))
    second = management.enumerate_creds_next()
    entries = {entry[RESULT.CREDENTIAL_ID]["id"]: entry for entry in (first, second)}
    assert entries[keyed.credential_id][RESULT.LARGE_BLOB_KEY] == keyed.large_blob_key
    assert RESULT.LARGE_BLOB_KEY not in entries[plain.credential_id]
    descriptor = {"type": "public-key", "id": keyed.credential_id}
    management.update_user_info(descriptor, {"id": user["id"], "name": "updated"})
    entries = management.enumerate_creds(client.sha256(RP_ID.encode()))
    entry = next(entry for entry in entries if entry[RESULT.CREDENTIAL_ID] == descriptor)
    assert entry[RESULT.LARGE_BLOB_KEY] == keyed.large_blob_key
    management.delete_cred(descriptor)
    assert _read(ctap) == before
    assert LargeBlobs(ctap).get_blob(keyed.large_blob_key) == b"retained after deletion"
    with pytest.raises(CtapError) as error:
        client.authenticate(ctap, keyed, extensions={"largeBlobKey": True})
    assert error.value.code == ERR.NO_CREDENTIALS
