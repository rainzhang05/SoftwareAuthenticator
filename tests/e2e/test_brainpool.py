"""Raw Python FIDO HID requests with independent Brainpool verification."""
import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
import ctap as client


@pytest.mark.parametrize("alg", [client.ESB256, client.ESB384])
@pytest.mark.parametrize("rk", [False, True])
@pytest.mark.parametrize("policy", [1, 2, 3])
@pytest.mark.parametrize("protocol_class", [PinProtocolV1, PinProtocolV2])
def test_brainpool_modalities_pin_protection_and_management(ctap, alg, rk, policy, protocol_class):
    rp, pin = "brainpool.e2e.example", "4821"
    protocol = protocol_class()
    ClientPin(ctap, protocol).set_pin(pin)
    auth = client.pin_uv_auth(ctap, protocol, pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp)
    extensions = {"credProtect": policy, "credBlob": b"brainpool", "hmac-secret": True, "thirdPartyPayment": True}
    if rk:
        extensions["largeBlobKey"] = True
    user = client.user_entity("brainpool")
    credential = client.register(ctap, rp, alg, user=user, options={"rk": rk}, extensions=extensions, uv=True, **auth)
    assert len(credential.credential_id) == 33 and credential.credential_id[0] == int(rk)
    for count in (1, 2):
        auth = client.pin_uv_auth(ctap, protocol, pin, ClientPin.PERMISSION.GET_ASSERTION, rp)
        outputs, data = client.authenticate(ctap, credential, uv=True,
                                            extensions={"credBlob": True, "thirdPartyPayment": True}, **auth)
        assert data.sign_count == count
        assert data.extensions == {"credBlob": b"brainpool", "thirdPartyPayment": True}
        assert (4 in outputs) == rk
    token = ClientPin(ctap, protocol).get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    manager = CredentialManagement(ctap, protocol, token)
    metadata = manager.get_metadata()
    assert metadata[1] == int(rk)
    if rk:
        entries = manager.enumerate_creds(client.sha256(rp.encode()))
        assert len(entries) == 1 and entries[0][8] == credential.public_key
        manager.update_user_info({"type": "public-key", "id": credential.credential_id},
                                 {"id": user["id"], "name": "updated", "displayName": "Updated"})
        manager.delete_cred({"type": "public-key", "id": credential.credential_id})
        with pytest.raises(CtapError) as failure:
            auth = client.pin_uv_auth(ctap, protocol, pin, ClientPin.PERMISSION.GET_ASSERTION, rp)
            client.authenticate(ctap, credential, uv=True, **auth)
        assert failure.value.code == CtapError.ERR.NO_CREDENTIALS
