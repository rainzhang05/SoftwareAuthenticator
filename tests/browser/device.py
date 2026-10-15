"""Fixture setup/read-only inspection on ONLY the newly owned UHID node.

No credentials are created here. Browser acceptance credentials always come
from navigator.credentials.create. PIN/token values arrive via stdin only.
"""
import json
import sys

import server as rp
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2


def operate(request):
    with rp.rc.open_device(request["node"]) as device:
        ctap = Ctap2(device)
        client = ClientPin(ctap)
        if request["operation"] == "setup":
            client.set_pin(request["pin"])
            info = Ctap2(device).info
            algorithms = [a["alg"] for a in info.algorithms]
            if algorithms != [a.identifier for a in rp.rc.ALGORITHMS]:
                raise ValueError("daemon algorithm inventory differs from independent client")
            return {"aaguid": bytes(info.aaguid).hex(), "versions": info.versions,
                    "algorithms": algorithms, "options": info.options,
                    "max_creds_in_list": info.max_creds_in_list,
                    "max_cred_id_length": info.max_cred_id_length}
        if request["operation"] != "enumerate":
            raise ValueError("unknown fixture operation")
        token = client.get_pin_token(request["pin"], ClientPin.PERMISSION.CREDENTIAL_MGMT)
        manager = CredentialManagement(ctap, client.protocol, token)
        entries = manager.enumerate_creds(rp.rc.sha256(b"localhost"))
        result = CredentialManagement.RESULT
        return [{"id": rp.b64u(entry[result.CREDENTIAL_ID]["id"]),
                 "user": {"name": entry[result.USER].get("name"),
                          "id": rp.b64u(entry[result.USER]["id"])}} for entry in entries]


if __name__ == "__main__":
    try:
        print(json.dumps(operate(json.load(sys.stdin))))
    except Exception as error:
        print(json.dumps({"error": type(error).__name__}))
        sys.exit(1)
