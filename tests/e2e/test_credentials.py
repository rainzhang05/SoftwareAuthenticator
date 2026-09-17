"""Registration, authentication, discoverable credentials and reset."""

import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2

import ctap as client

RP_ID = "e2e.example"

ALGORITHMS = [
    pytest.param(client.ES256, id="ES256"),
    *(
        pytest.param(alg, id=f"ML-DSA-{name}")
        for alg, name in ((client.ML_DSA_44, 44), (client.ML_DSA_65, 65), (client.ML_DSA_87, 87))
    ),
]


@pytest.mark.parametrize("alg", ALGORITHMS)
def test_register_and_authenticate(ctap: Ctap2, alg):
    credential = client.register(ctap, RP_ID, alg)

    _, first = client.authenticate(ctap, credential)
    _, second = client.authenticate(ctap, credential)
    assert first.sign_count > credential.auth_data.sign_count, "signature counter did not increase"
    assert second.sign_count > first.sign_count, "signature counter did not increase"


def _discoverable(ctap: Ctap2, count: int):
    registered = {}
    for index in range(count):
        user = client.user_entity(f"user{index}")
        credential = client.register(ctap, RP_ID, client.ES256, user=user, options={"rk": True})
        registered[credential.credential_id] = (credential, user)

    client_data_hash = os.urandom(32)
    responses = [client.get_assertion(ctap, RP_ID, client_data_hash)]
    if count > 1:
        assert responses[0].get(5) == count, "numberOfCredentials"
    else:
        assert 5 not in responses[0]
    responses += [client.get_next_assertion(ctap) for _ in range(count - 1)]

    seen = set()
    for response in responses:
        credential_id = response[1]["id"]
        credential, user = registered[credential_id]
        assert response[4]["id"] == user["id"]
        auth_data = client.AuthData.parse(response[2])
        auth_data.check(RP_ID, up=True, uv=False, at=False)
        client.verify_signature(credential.public_key, response[2] + client_data_hash, response[3])
        seen.add(credential_id)
    assert seen == set(registered)

    with pytest.raises(CtapError) as excinfo:
        client.get_next_assertion(ctap)
    assert excinfo.value.code == CtapError.ERR.NOT_ALLOWED


def test_discoverable_credential(ctap: Ctap2):
    _discoverable(ctap, 1)


def test_several_discoverable_credentials(ctap: Ctap2):
    _discoverable(ctap, 3)


def test_reset_removes_credentials(ctap: Ctap2):
    credential = client.register(ctap, RP_ID, client.ES256, options={"rk": True})
    client.authenticate(ctap, credential)

    ctap.reset()

    for allow_ids in ([credential.credential_id], None):
        with pytest.raises(CtapError) as excinfo:
            client.get_assertion(ctap, RP_ID, os.urandom(32), allow_ids)
        assert excinfo.value.code == CtapError.ERR.NO_CREDENTIALS

    # The store is usable again after the reset.
    client.authenticate(ctap, client.register(ctap, RP_ID, client.ES256))
