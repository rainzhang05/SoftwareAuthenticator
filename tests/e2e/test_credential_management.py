"""authenticatorCredentialManagement (CTAP 2.3 §6.8) through python-fido2's
CredentialManagement, with pinUvAuthTokens of PIN/UV auth protocols 1 and 2.

Every test starts from the same credentials: two discoverable credentials of
one relying party, one of them ML-DSA-87 and the other created with
credProtect, a discoverable credential of a second relying party, and a
non-discoverable credential of the first, which credential management does not
manage. They are created before the PIN is set, because once a PIN is set a
discoverable credential needs a pinUvAuthParam (CTAP 2.3 §6.1.2 step 7).

Collecting user presence clears the pinUvAuthToken's permissions (CTAP 2.3
§6.1.2 step 14, §6.2.2 step 9), so the token is taken after the last
registration, and a test makes assertions only once it is done with it.
"""

import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2

import ctap as client

RP_A = "a.credman.e2e.example"
RP_B = "b.credman.e2e.example"
PIN = "4821"

RESULT = CredentialManagement.RESULT


@pytest.fixture
def capacity(ctap: Ctap2) -> int:
    """How many credentials the freshly reset authenticator has room for:
    remainingDiscoverableCredentials (0x14) of authenticatorGetInfo (CTAP 2.3
    §6.4)."""
    return ctap.send_cbor(Ctap2.CMD.GET_INFO)[0x14]


@pytest.fixture
def registered(ctap: Ctap2, capacity) -> dict[str, tuple[client.Credential, dict]]:
    """The credentials, with their users, by user name; then a PIN is set."""
    registered = {}
    for name, rp_id, alg, options, extensions in (
        # ML-DSA-87: the 2592-byte public key spreads each enumeration response
        # for this credential over dozens of CTAPHID packets.
        ("alice", RP_A, client.ML_DSA_87, {"rk": True}, None),
        # userVerificationOptionalWithCredentialIDList (CTAP 2.3 §12.1).
        ("bob", RP_A, client.ES256, {"rk": True}, {"credProtect": 2}),
        ("carol", RP_B, client.ES256, {"rk": True}, None),
        ("dave", RP_A, client.ES256, {"rk": False}, None),
    ):
        user = client.user_entity(name)
        credential = client.register(ctap, rp_id, alg, user=user, options=options, extensions=extensions)
        registered[name] = (credential, user)
    assert registered["bob"][0].auth_data.extensions == {"credProtect": 2}
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    return registered


@pytest.fixture(params=[pytest.param(PinProtocolV1, id="protocol-1"), pytest.param(PinProtocolV2, id="protocol-2")])
def credman(request, ctap: Ctap2, registered) -> CredentialManagement:
    """Credential management with a pinUvAuthToken that has the cm permission
    and no permissions RP ID, as getCredsMetadata and enumerateRPs require
    (CTAP 2.3 §6.8.2, §6.8.3)."""
    protocol = request.param()
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(ctap, protocol, token)


def _rp_id_hash(rp_id: str) -> bytes:
    return client.sha256(rp_id.encode())


def _descriptor(credential: client.Credential) -> dict:
    """A PublicKeyCredentialDescriptor, as a plain mapping for python-fido2."""
    return {"type": "public-key", "id": credential.credential_id}


def _enumerated(credman: CredentialManagement, rp_id: str) -> dict:
    """The enumerated credentials of `rp_id`, by credential ID."""
    return {entry[RESULT.CREDENTIAL_ID]["id"]: entry for entry in credman.enumerate_creds(_rp_id_hash(rp_id))}


def test_metadata_counts_discoverable_credentials_and_free_space(ctap: Ctap2, capacity, registered, credman):
    """getCredsMetadata (CTAP 2.3 §6.8.2): existingResidentCredentialsCount
    counts the discoverable credentials, and
    maxPossibleRemainingResidentCredentialsCount is the room left in the store,
    which non-discoverable credentials take up as well: this authenticator
    stores every credential, and only a credential's ID says whether it is
    discoverable (is_discoverable in crates/pqkey-ctap/src/ctap/storage.rs).
    getInfo's remainingDiscoverableCredentials says the same."""
    metadata = credman.get_metadata()
    assert metadata[RESULT.EXISTING_CRED_COUNT] == 3
    assert metadata[RESULT.MAX_REMAINING_COUNT] == capacity - len(registered)
    assert ctap.send_cbor(Ctap2.CMD.GET_INFO)[0x14] == capacity - len(registered)


def test_enumerate_rps(credman):
    """enumerateRPsBegin and enumerateRPsGetNextRP (CTAP 2.3 §6.8.3): every
    relying party with a discoverable credential once, with the SHA-256 hash of
    its RP ID, and their number in the first response only."""
    rps = credman.enumerate_rps()
    assert sorted((rp[RESULT.RP]["id"], rp[RESULT.RP_ID_HASH]) for rp in rps) == [
        (RP_A, _rp_id_hash(RP_A)),
        (RP_B, _rp_id_hash(RP_B)),
    ]
    assert rps[0][RESULT.TOTAL_RPS] == 2
    assert RESULT.TOTAL_RPS not in rps[1]


def test_enumerate_credentials_of_an_rp(registered, credman):
    """enumerateCredentialsBegin and enumerateCredentialsGetNextCredential
    (CTAP 2.3 §6.8.4): the relying party's discoverable credentials, each with
    its user, credential ID, public key and credProtect policy. Its
    non-discoverable credential is not among them."""
    enumerated = _enumerated(credman, RP_A)
    assert set(enumerated) == {registered[name][0].credential_id for name in ("alice", "bob")}

    # alice's credential has the default policy, userVerificationOptional (1).
    for name, cred_protect in (("alice", 1), ("bob", 2)):
        credential, user = registered[name]
        entry = enumerated[credential.credential_id]
        assert entry[RESULT.USER] == user
        assert entry[RESULT.CREDENTIAL_ID] == {"type": "public-key", "id": credential.credential_id}
        assert entry[RESULT.PUBLIC_KEY] == credential.public_key
        assert entry[RESULT.CRED_PROTECT] == cred_protect


def test_only_the_first_credential_comes_with_the_total(registered, credman):
    """totalCredentials (0x09) is a member of the enumerateCredentialsBegin
    response, and not of the enumerateCredentialsGetNextCredential response
    (CTAP 2.3 §6.8.4)."""
    first = credman.enumerate_creds_begin(_rp_id_hash(RP_A))
    assert first[RESULT.TOTAL_CREDENTIALS] == 2
    second = credman.enumerate_creds_next()
    members = sorted(second)
    assert RESULT.TOTAL_CREDENTIALS not in members
    assert {first[RESULT.CREDENTIAL_ID]["id"], second[RESULT.CREDENTIAL_ID]["id"]} == {
        registered[name][0].credential_id for name in ("alice", "bob")
    }


def test_update_user_information(registered, credman):
    """updateUserInformation (CTAP 2.3 §6.8.6) replaces the name and
    displayName of the credential's user, whom the user ID identifies, and
    removes those the new user entity leaves out."""
    credential, user = registered["alice"]
    updated = {"id": user["id"], "name": "alice@example.com", "displayName": "Alice Liddell"}
    credman.update_user_info(_descriptor(credential), updated)

    enumerated = _enumerated(credman, RP_A)
    assert enumerated[credential.credential_id][RESULT.USER] == updated
    other, other_user = registered["bob"]
    assert enumerated[other.credential_id][RESULT.USER] == other_user

    credman.update_user_info(_descriptor(credential), {"id": user["id"], "name": "alice"})
    assert _enumerated(credman, RP_A)[credential.credential_id][RESULT.USER] == {"id": user["id"], "name": "alice"}


def test_delete_credential(ctap: Ctap2, capacity, registered, credman):
    """deleteCredential (CTAP 2.3 §6.8.5) removes the credential: it is no
    longer enumerated or counted, and getAssertion does not find it even by its
    ID (§6.2.2 step 7). The relying party's other credential is untouched."""
    deleted, kept = registered["alice"][0], registered["bob"][0]
    credman.delete_cred(_descriptor(deleted))

    assert set(_enumerated(credman, RP_A)) == {kept.credential_id}
    metadata = credman.get_metadata()
    assert metadata[RESULT.EXISTING_CRED_COUNT] == 2
    assert metadata[RESULT.MAX_REMAINING_COUNT] == capacity - len(registered) + 1

    # Assertions only now that the pinUvAuthToken is no longer needed.
    with pytest.raises(CtapError) as excinfo:
        client.get_assertion(ctap, RP_A, os.urandom(32), [deleted.credential_id])
    assert excinfo.value.code == CtapError.ERR.NO_CREDENTIALS
    client.authenticate(ctap, kept)


def test_an_rp_without_credentials_has_none_to_enumerate(credman):
    """enumerateCredentialsBegin for an RP ID hash without discoverable
    credentials is refused with CTAP2_ERR_NO_CREDENTIALS (CTAP 2.3 §6.8.4)."""
    with pytest.raises(CtapError) as excinfo:
        credman.enumerate_creds_begin(_rp_id_hash("none.credman.e2e.example"))
    assert excinfo.value.code == CtapError.ERR.NO_CREDENTIALS
