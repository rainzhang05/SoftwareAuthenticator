"""Self-check of the ML-DSA verifier the credential tests rely on.

The credential tests check the authenticator's ML-DSA signatures with
ctap.verify_signature. This runs that verifier against signatures made by
pyca/cryptography's OpenSSL-backed ML-DSA, independent of the authenticator,
so a missing backend or a broken verifier cannot make those tests pass or fail
for the wrong reason.
"""

import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

import ctap as client

PRIVATE_KEYS = {
    client.ML_DSA_44: mldsa.MLDSA44PrivateKey,
    client.ML_DSA_65: mldsa.MLDSA65PrivateKey,
    client.ML_DSA_87: mldsa.MLDSA87PrivateKey,
}


@pytest.mark.parametrize(
    "alg", [pytest.param(alg, id=f"ML-DSA-{name}") for alg, name in zip(PRIVATE_KEYS, (44, 65, 87))]
)
def test_verifier_accepts_only_pure_empty_context_signatures(alg):
    private_key = PRIVATE_KEYS[alg].generate()
    cose_key = {1: client.COSE_KTY_AKP, 3: alg, -1: private_key.public_key().public_bytes_raw()}
    client.check_public_key(cose_key, alg)
    message = os.urandom(37) + os.urandom(32)

    client.verify_signature(cose_key, message, private_key.sign(message))

    rejected = {
        "other message": (message[:-1] + bytes([message[-1] ^ 1]), private_key.sign(message)),
        "non-empty context": (message, private_key.sign(message, b"webauthn")),
        "other key": (message, PRIVATE_KEYS[alg].generate().sign(message)),
    }
    for case, (signed, signature) in rejected.items():
        with pytest.raises(InvalidSignature):
            client.verify_signature(cose_key, signed, signature)
            pytest.fail(f"accepted a signature with {case}")
