"""Synthetic RP/verifier unit fixtures, never real-browser acceptance results."""
import contextlib
import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from fido2 import cbor

import server as rp


class RP(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for name, value in {"DATA": Path(self.temp.name), "DB_PATH": Path(self.temp.name) / "db.json",
                            "RESULTS": Path(self.temp.name) / "results.jsonl", "PENDING": {}}.items():
            old = getattr(rp, name)
            self.addCleanup(setattr, rp, name, old)
            setattr(rp, name, value)
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stdout(self.output)
        self.capture.__enter__()
        self.addCleanup(self.capture.__exit__, None, None, None)

    def client_data(self, options, kind):
        return rp.b64u(json.dumps({"type": "webauthn." + kind, "challenge": options["publicKey"]["challenge"],
                                  "origin": f"http://localhost:{rp.PORT}", "crossOrigin": False}).encode())

    def register(self, alg=-7, rk=False, uv=False):
        request = {"username": "alice", "algs": [alg], "label": "unit", "fixtureId": "unit",
                   "residentKey": "required" if rk else "discouraged",
                   "userVerification": "required" if uv else "discouraged"}
        opts = rp.register_options(request)
        if alg == -7:
            key = ec.generate_private_key(ec.SECP256R1())
            numbers = key.public_key().public_numbers()
            cose = {1: 2, 3: alg, -1: 1, -2: numbers.x.to_bytes(32), -3: numbers.y.to_bytes(32)}
            self.sign = lambda data: key.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            numbers = key.public_key().public_numbers()
            cose = {1: 3, 3: alg, -1: numbers.n.to_bytes(256), -2: numbers.e.to_bytes(3)}
            self.sign = lambda data: key.sign(data, padding.PKCS1v15(), hashes.SHA384())
        identifier = bytes([1 if rk else (0 if alg != -7 else 2)]) + b"x" * (32 if rk or alg != -7 else 106)
        self.identifier = rp.b64u(identifier)
        raw = hashlib.sha256(b"localhost").digest() + bytes([0x41 | (4 if uv else 0)]) + bytes(4)
        raw += bytes(16) + struct.pack(">H", len(identifier)) + identifier + cbor.encode(cose)
        credential = {"id": self.identifier, "rawId": self.identifier, "type": "public-key",
                      "response": {"clientDataJSON": self.client_data(opts, "create"),
                                   "attestationObject": rp.b64u(cbor.encode({"fmt": "none", "authData": raw, "attStmt": {}}))}}
        return rp.register_verify({"ceremonyId": opts["ceremonyId"], "credential": credential})

    def login(self, *, count=1, uv=False, change=None, **request):
        opts = rp.login_options({"username": "alice", "allow": "user", **request})
        client = self.client_data(opts, "get")
        raw = hashlib.sha256(b"localhost").digest() + bytes([1 | (4 if uv else 0)]) + struct.pack(">I", count)
        credential = {"id": self.identifier, "rawId": self.identifier, "type": "public-key",
                      "response": {"clientDataJSON": client, "authenticatorData": rp.b64u(raw),
                                   "signature": rp.b64u(self.sign(raw + hashlib.sha256(rp.unb64u(client)).digest()))}}
        if change:
            change(credential)
        return rp.login_verify({"ceremonyId": opts["ceremonyId"], "credential": credential})

    def test_valid_and_corrupted_signature_and_counter(self):
        self.assertEqual(self.register()["outcome"], "PASS")
        self.assertEqual(self.login()["outcome"], "PASS")
        self.assertEqual(self.login()["outcome"], "FAIL")
        self.assertEqual(self.login(count=2, change=lambda c: c["response"].update(signature=rp.b64u(bytes(70))))["outcome"], "FAIL")

    def test_uv_allow_list_and_expected_selection(self):
        self.register(rk=True, uv=True)
        self.assertEqual(self.login(userVerification="required")["outcome"], "FAIL")
        self.assertEqual(self.login(allow="cred:" + rp.b64u(b"other"))["outcome"], "FAIL")
        self.assertEqual(self.login(expectedCredential="other")["outcome"], "FAIL")
        self.assertEqual(self.login(allow="empty")["outcome"], "FAIL")  # missing userHandle

    def test_challenge_origin_and_type_are_independently_checked(self):
        self.register()
        for field, value in [("origin", "https://evil.example"), ("challenge", "bad"), ("type", "webauthn.create")]:
            def change(credential):
                data = json.loads(rp.unb64u(credential["response"]["clientDataJSON"]))
                data[field] = value
                credential["response"]["clientDataJSON"] = rp.b64u(json.dumps(data).encode())
            self.assertEqual(self.login(change=change)["outcome"], "FAIL")

    def test_library_limit_never_replaces_independent_verification(self):
        self.assertEqual(self.register(alg=-258)["outcome"], "PASS")
        result = self.login()
        self.assertEqual(result["outcome"], "PASS")
        self.assertIn("unsupported_library_algorithm", json.dumps(result))
        self.assertEqual(self.login(count=2, change=lambda c: c["response"].update(signature=rp.b64u(bytes(256))))["outcome"], "FAIL")

    def test_current_id_forms(self):
        for length, marker, want in [(33, 0, False), (33, 1, True), (107, 2, False), (33, 2, None), (0, 0, None)]:
            self.assertIs(rp.credential_modality(bytes([marker]) * length), want)

    def test_prf_secrets_are_absent_from_public_evidence(self):
        self.register()
        secret = rp.b64u(b"s" * 32)
        def extension(credential):
            credential["clientExtensionResults"] = {"prf": {"results": {"first": secret}}}
        for count in (1, 2):
            result = self.login(count=count, prfSalt1="A", change=extension)
            self.assertEqual(result["outcome"], "PASS")
            self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn(secret, rp.RESULTS.read_text() + self.output.getvalue())
        self.assertIn("sha256", json.dumps(result["credential"]["clientExtensionResults"]))


if __name__ == "__main__":
    unittest.main()
