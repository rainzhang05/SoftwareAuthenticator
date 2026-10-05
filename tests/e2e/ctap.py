"""CTAP2 client helpers for the end-to-end tests.

python-fido2 is used only as a transport (CTAPHID framing, canonical CBOR) and
for the PIN/UV auth protocols. Requests are built here so the tests control
every parameter, and responses are taken apart here, without python-fido2's
response classes, so the checks do not depend on what python-fido2 accepts.
Signatures are verified with pyca/cryptography.
"""

from __future__ import annotations

import hashlib
import os
import select
import struct
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, mldsa, padding, rsa
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.linux import LinuxCtapHidConnection, get_descriptor

# COSE algorithm identifiers, each described once in ALGORITHMS below.
ES256 = -7
ML_DSA_44 = -48
ML_DSA_65 = -49
ML_DSA_87 = -50
ESP256 = -9
ES384 = -35
ESP384 = -51
ES512 = -36
ESP512 = -52
ES256K = -47
EDDSA = -8
ED25519 = -19
ED448 = -53
RS256 = -257
RS384 = -258
RS512 = -259
PS256 = -37
PS384 = -38
PS512 = -39

COSE_KTY_OKP = 1
COSE_KTY_EC2 = 2
COSE_KTY_AKP = 7
COSE_KTY_RSA = 3
COSE_CRV_P256 = 1
COSE_CRV_P384 = 2
COSE_CRV_P521 = 3
COSE_CRV_SECP256K1 = 8
COSE_CRV_ED25519 = 6
COSE_CRV_ED448 = 7

# The AAGUID pqkey uses unless --aaguid is given.
DEFAULT_AAGUID = bytes.fromhex("5931e805a1664eb7845a7f6aa93d9cd8")

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40
FLAG_ED = 0x80

# How long to wait for any single CTAPHID packet. Operations complete in
# milliseconds; this only turns a hung authenticator into a test failure.
READ_TIMEOUT_S = 15.0


class _TimeoutConnection(LinuxCtapHidConnection):
    """python-fido2's hidraw connection, with a timeout on every read."""

    def read_packet(self) -> bytes:
        ready, _, _ = select.select([self.handle], [], [], READ_TIMEOUT_S)
        if not ready:
            raise TimeoutError(f"no CTAPHID packet within {READ_TIMEOUT_S}s")
        return super().read_packet()


def open_device(path: str) -> CtapHidDevice:
    """Open the hidraw node and allocate a CTAPHID channel (CTAPHID_INIT)."""
    descriptor = get_descriptor(path)
    return CtapHidDevice(descriptor, _TimeoutConnection(descriptor))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def user_entity(name: str) -> dict[str, Any]:
    return {"id": os.urandom(16), "name": name, "displayName": name.title()}


@dataclass
class AuthData:
    """authenticatorData, parsed by hand (WebAuthn Level 3, 6.1)."""

    raw: bytes
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None
    public_key: dict | None = None
    extensions: dict | None = None

    @classmethod
    def parse(cls, raw: bytes) -> "AuthData":
        from fido2 import cbor

        if len(raw) < 37:
            raise ValueError(f"authData is only {len(raw)} bytes")
        rp_id_hash, flags, sign_count = raw[:32], raw[32], struct.unpack(">I", raw[33:37])[0]
        parsed = cls(raw, rp_id_hash, flags, sign_count)
        rest = raw[37:]
        if flags & FLAG_AT:
            if len(rest) < 18:
                raise ValueError("attested credential data is truncated")
            parsed.aaguid = rest[:16]
            (id_len,) = struct.unpack(">H", rest[16:18])
            parsed.credential_id = rest[18 : 18 + id_len]
            if len(parsed.credential_id) != id_len:
                raise ValueError("credential ID is truncated")
            parsed.public_key, rest = cbor.decode_from(rest[18 + id_len :])
        if flags & FLAG_ED:
            parsed.extensions, rest = cbor.decode_from(rest)
        if rest:
            raise ValueError(f"{len(rest)} unexpected trailing bytes in authData")
        return parsed

    def check(self, rp_id: str, *, up: bool, uv: bool, at: bool) -> None:
        assert self.rp_id_hash == sha256(rp_id.encode()), "RP ID hash mismatch"
        assert bool(self.flags & FLAG_UP) == up, f"UP flag wrong in flags {self.flags:#04x}"
        assert bool(self.flags & FLAG_UV) == uv, f"UV flag wrong in flags {self.flags:#04x}"
        assert bool(self.flags & FLAG_AT) == at, f"AT flag wrong in flags {self.flags:#04x}"
        assert not self.flags & 0x3A, f"reserved or backup flags set in {self.flags:#04x}"


def _check_ec2(crv: int, coordinate_size: int) -> Callable[[Mapping[int, Any]], None]:
    """An EC2 key on curve `crv` with both coordinates, each
    `coordinate_size` bytes (WebAuthn Level 3, 5.8.5; RFC 8812, 3.1 for
    secp256k1)."""

    def check(cose_key: Mapping[int, Any]) -> None:
        assert cose_key.get(1) == COSE_KTY_EC2
        assert cose_key.get(-1) == crv, f"crv {cose_key.get(-1)} != {crv}"
        assert len(cose_key.get(-2, b"")) == coordinate_size
        assert len(cose_key.get(-3, b"")) == coordinate_size
        assert set(cose_key) == {1, 3, -1, -2, -3}, f"unexpected labels {set(cose_key)}"

    return check


def _verify_ecdsa(
    curve: ec.EllipticCurve, hash_algorithm: hashes.HashAlgorithm
) -> Callable[[Mapping[int, Any], bytes, bytes], None]:
    """ECDSA on `curve` over the message's `hash_algorithm` digest, the
    signature DER-encoded (WebAuthn Level 3, 6.5.5)."""

    def verify(cose_key: Mapping[int, Any], message: bytes, signature: bytes) -> None:
        x = int.from_bytes(cose_key[-2], "big")
        y = int.from_bytes(cose_key[-3], "big")
        key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        key.verify(signature, message, ec.ECDSA(hash_algorithm))

    return verify


def _check_okp(crv: int, public_key_size: int) -> Callable[[Mapping[int, Any]], None]:
    """An OKP key (RFC 9053, 7.2) on curve `crv`, whose x is the
    `public_key_size`-byte public key as RFC 8032 encodes it (WebAuthn Level
    3, 5.8.5)."""

    def check(cose_key: Mapping[int, Any]) -> None:
        assert cose_key.get(1) == COSE_KTY_OKP
        assert cose_key.get(-1) == crv, f"crv {cose_key.get(-1)} != {crv}"
        assert len(cose_key.get(-2, b"")) == public_key_size
        assert set(cose_key) == {1, 3, -1, -2}, f"unexpected labels {set(cose_key)}"

    return check


def _verify_eddsa(public_key_class: Any, signature_size: int) -> Callable[[Mapping[int, Any], bytes, bytes], None]:
    """Pure EdDSA (RFC 8032) over the message itself, the signature R || S
    as RFC 8032 encodes it (RFC 9053, 2.2), verified by OpenSSL through
    cryptography, whose Ed448 has an empty context."""

    def verify(cose_key: Mapping[int, Any], message: bytes, signature: bytes) -> None:
        if len(signature) != signature_size:
            raise InvalidSignature(f"EdDSA signature is {len(signature)} bytes")
        public_key_class.from_public_bytes(cose_key[-2]).verify(signature, message)

    return verify


def _check_rsa(cose_key: Mapping[int, Any]) -> None:
    """RSA-2048 with e = 65537, unsigned minimal byte strings (RFC 8230, 4)."""
    assert cose_key.get(1) == COSE_KTY_RSA
    assert set(cose_key) == {1, 3, -1, -2}, f"unexpected labels {set(cose_key)}"
    n = cose_key.get(-1, b"")
    assert isinstance(n, bytes) and len(n) == 256 and n[0] & 0x80
    assert cose_key.get(-2) == b"\x01\x00\x01"


def _verify_rsa(
    hash_algorithm: hashes.HashAlgorithm, *, pss: bool
) -> Callable[[Mapping[int, Any], bytes, bytes], None]:
    """RFC 8017 signatures, raw 256-byte values. PSS uses the same hash for
    MGF1 and a hash-sized salt (RFC 8230, 2). Use cryptography: python-fido2
    2.2.1 parses RS384/512 and PS384/512 as UnsupportedKey."""

    def verify(cose_key: Mapping[int, Any], message: bytes, signature: bytes) -> None:
        n = int.from_bytes(cose_key[-1], "big")
        e = int.from_bytes(cose_key[-2], "big")
        if len(signature) != 256 or int.from_bytes(signature, "big") >= n:
            raise InvalidSignature("RSA signature must be 256 bytes and below n")
        scheme = (
            padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=hash_algorithm.digest_size)
            if pss else padding.PKCS1v15()
        )
        rsa.RSAPublicNumbers(e, n).public_key().verify(signature, message, scheme, hash_algorithm)

    return verify


def _check_akp(public_key_size: int) -> Callable[[Mapping[int, Any]], None]:
    """An AKP key (RFC 9964) whose public key is `public_key_size` bytes."""

    def check(cose_key: Mapping[int, Any]) -> None:
        assert cose_key.get(1) == COSE_KTY_AKP
        assert len(cose_key.get(-1, b"")) == public_key_size
        assert set(cose_key) == {1, 3, -1}, f"unexpected labels {set(cose_key)}"

    return check


def _verify_mldsa(public_key_class: Any, signature_size: int) -> Callable[[Mapping[int, Any], bytes, bytes], None]:
    """Pure ML-DSA (FIPS 204 ML-DSA.Verify) with an empty context, verified by
    the OpenSSL implementation in cryptography's wheels, not by RustCrypto's
    ml-dsa crate the authenticator signs with."""

    def verify(cose_key: Mapping[int, Any], message: bytes, signature: bytes) -> None:
        if len(signature) != signature_size:
            raise InvalidSignature(f"ML-DSA signature is {len(signature)} bytes")
        public_key_class.from_public_bytes(cose_key[-1]).verify(signature, message)

    return verify


@dataclass(frozen=True)
class Algorithm:
    """A signature algorithm the key supports: how its COSE_Key looks and how
    its signatures verify."""

    identifier: int
    name: str
    check_public_key: Callable[[Mapping[int, Any]], None]
    verify: Callable[[Mapping[int, Any], bytes, bytes], None]


# Every signature algorithm the key supports, in the order getInfo lists them:
# the key's own table is CoseAlg in crates/pqkey-ctap/src/crypto/alg.rs. The
# ML-DSA public key and signature sizes are FIPS 204's, table 2; each ECDSA
# curve's coordinates are as long as its field elements; EdDSA public keys and
# signatures are as long as RFC 8032 encodes them; RSA uses 2048-bit keys
# and 256-byte raw signatures (RFC 8017, 8; RFC 8230, 6.1).
ALGORITHMS = (
    Algorithm(ES256, "ES256", _check_ec2(COSE_CRV_P256, 32), _verify_ecdsa(ec.SECP256R1(), hashes.SHA256())),
    Algorithm(ML_DSA_44, "ML-DSA-44", _check_akp(1312), _verify_mldsa(mldsa.MLDSA44PublicKey, 2420)),
    Algorithm(ML_DSA_65, "ML-DSA-65", _check_akp(1952), _verify_mldsa(mldsa.MLDSA65PublicKey, 3309)),
    Algorithm(ML_DSA_87, "ML-DSA-87", _check_akp(2592), _verify_mldsa(mldsa.MLDSA87PublicKey, 4627)),
    Algorithm(ESP256, "ESP256", _check_ec2(COSE_CRV_P256, 32), _verify_ecdsa(ec.SECP256R1(), hashes.SHA256())),
    Algorithm(ES384, "ES384", _check_ec2(COSE_CRV_P384, 48), _verify_ecdsa(ec.SECP384R1(), hashes.SHA384())),
    Algorithm(ESP384, "ESP384", _check_ec2(COSE_CRV_P384, 48), _verify_ecdsa(ec.SECP384R1(), hashes.SHA384())),
    Algorithm(ES512, "ES512", _check_ec2(COSE_CRV_P521, 66), _verify_ecdsa(ec.SECP521R1(), hashes.SHA512())),
    Algorithm(ESP512, "ESP512", _check_ec2(COSE_CRV_P521, 66), _verify_ecdsa(ec.SECP521R1(), hashes.SHA512())),
    Algorithm(ES256K, "ES256K", _check_ec2(COSE_CRV_SECP256K1, 32), _verify_ecdsa(ec.SECP256K1(), hashes.SHA256())),
    Algorithm(EDDSA, "EdDSA", _check_okp(COSE_CRV_ED25519, 32), _verify_eddsa(ed25519.Ed25519PublicKey, 64)),
    Algorithm(ED25519, "Ed25519", _check_okp(COSE_CRV_ED25519, 32), _verify_eddsa(ed25519.Ed25519PublicKey, 64)),
    Algorithm(ED448, "Ed448", _check_okp(COSE_CRV_ED448, 57), _verify_eddsa(ed448.Ed448PublicKey, 114)),
    Algorithm(RS256, "RS256", _check_rsa, _verify_rsa(hashes.SHA256(), pss=False)),
    Algorithm(RS384, "RS384", _check_rsa, _verify_rsa(hashes.SHA384(), pss=False)),
    Algorithm(RS512, "RS512", _check_rsa, _verify_rsa(hashes.SHA512(), pss=False)),
    Algorithm(PS256, "PS256", _check_rsa, _verify_rsa(hashes.SHA256(), pss=True)),
    Algorithm(PS384, "PS384", _check_rsa, _verify_rsa(hashes.SHA384(), pss=True)),
    Algorithm(PS512, "PS512", _check_rsa, _verify_rsa(hashes.SHA512(), pss=True)),
)
BY_IDENTIFIER = {algorithm.identifier: algorithm for algorithm in ALGORITHMS}
NAMES = {algorithm.identifier: algorithm.name for algorithm in ALGORITHMS}


def check_public_key(cose_key: Mapping[int, Any], alg: int) -> None:
    """Check the COSE_Key structure of a key of algorithm `alg`."""
    assert cose_key.get(3) == alg, f"COSE alg {cose_key.get(3)} != {alg}"
    BY_IDENTIFIER[alg].check_public_key(cose_key)


def verify_signature(cose_key: Mapping[int, Any], message: bytes, signature: bytes) -> None:
    """Verify with pyca/cryptography, as the key's algorithm in ALGORITHMS
    does; raises InvalidSignature on failure."""
    alg = cose_key[3]
    if alg not in BY_IDENTIFIER:
        raise ValueError(f"unsupported COSE algorithm {alg}")
    BY_IDENTIFIER[alg].verify(cose_key, message, signature)


def verify_attestation(response: Mapping[int, Any], cose_key: Mapping[int, Any], client_data_hash: bytes) -> None:
    """Verify a packed or none attestation statement's signature."""
    fmt, auth_data, att_stmt = response[1], response[2], response[3]
    signed = auth_data + client_data_hash
    if fmt == "none":
        assert att_stmt == {}
    elif fmt == "packed":
        if "x5c" in att_stmt:
            assert att_stmt["alg"] == ES256, f"attestation alg {att_stmt['alg']}"
            certificate = x509.load_der_x509_certificate(att_stmt["x5c"][0])
            public_key = certificate.public_key()
            assert isinstance(public_key, ec.EllipticCurvePublicKey)
            public_key.verify(att_stmt["sig"], signed, ec.ECDSA(hashes.SHA256()))
        else:
            assert att_stmt["alg"] == cose_key[3]
            verify_signature(cose_key, signed, att_stmt["sig"])
    else:
        raise AssertionError(f"unexpected attestation format {fmt!r}")


def make_credential_request(rp_id: str, user: Mapping[str, Any], alg: int = ES256) -> bytes:
    """An encoded authenticatorMakeCredential request, for raw CTAPHID tests."""
    from fido2 import cbor

    return bytes([Ctap2.CMD.MAKE_CREDENTIAL]) + cbor.encode(
        {1: os.urandom(32), 2: {"id": rp_id}, 3: dict(user), 4: [{"type": "public-key", "alg": alg}]}
    )


def make_credential(
    ctap: Ctap2,
    rp_id: str,
    user: Mapping[str, Any],
    algs: list[int],
    client_data_hash: bytes,
    *,
    extensions: Mapping[str, Any] | None = None,
    options: Mapping[str, bool] | None = None,
    pin_uv_param: bytes | None = None,
    pin_uv_protocol: int | None = None,
) -> Mapping[int, Any]:
    request: dict[int, Any] = {
        1: client_data_hash,
        2: {"id": rp_id, "name": rp_id},
        3: dict(user),
        4: [{"type": "public-key", "alg": alg} for alg in algs],
    }
    if extensions:
        request[6] = dict(extensions)
    if options:
        request[7] = dict(options)
    if pin_uv_param is not None:
        request[8] = pin_uv_param
        request[9] = pin_uv_protocol
    return ctap.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, request)


def get_assertion(
    ctap: Ctap2,
    rp_id: str,
    client_data_hash: bytes,
    allow_ids: list[bytes] | None = None,
    *,
    extensions: Mapping[str, Any] | None = None,
    options: Mapping[str, bool] | None = None,
    pin_uv_param: bytes | None = None,
    pin_uv_protocol: int | None = None,
) -> Mapping[int, Any]:
    request: dict[int, Any] = {1: rp_id, 2: client_data_hash}
    if allow_ids is not None:
        request[3] = [{"type": "public-key", "id": cred_id} for cred_id in allow_ids]
    if extensions:
        request[4] = dict(extensions)
    if options:
        request[5] = dict(options)
    if pin_uv_param is not None:
        request[6] = pin_uv_param
        request[7] = pin_uv_protocol
    return ctap.send_cbor(Ctap2.CMD.GET_ASSERTION, request)


def get_next_assertion(ctap: Ctap2) -> Mapping[int, Any]:
    return ctap.send_cbor(Ctap2.CMD.GET_NEXT_ASSERTION)


@dataclass
class Credential:
    rp_id: str
    alg: int
    credential_id: bytes
    public_key: dict
    auth_data: AuthData


def register(
    ctap: Ctap2, rp_id: str, alg: int, *, uv: bool = False, client_data_hash: bytes | None = None, **kwargs
) -> Credential:
    """makeCredential, with every check that applies to any registration."""
    client_data_hash = client_data_hash or os.urandom(32)
    user = kwargs.pop("user", None) or user_entity("alice")
    response = make_credential(ctap, rp_id, user, [alg], client_data_hash, **kwargs)
    auth_data = AuthData.parse(response[2])
    auth_data.check(rp_id, up=True, uv=uv, at=True)
    assert auth_data.aaguid == DEFAULT_AAGUID
    assert auth_data.credential_id, "empty credential ID"
    check_public_key(auth_data.public_key, alg)
    verify_attestation(response, auth_data.public_key, client_data_hash)
    return Credential(rp_id, alg, auth_data.credential_id, auth_data.public_key, auth_data)


def authenticate(
    ctap: Ctap2,
    credential: Credential,
    allow_list: bool = True,
    *,
    uv: bool = False,
    client_data_hash: bytes | None = None,
    **kwargs,
) -> tuple[Mapping[int, Any], AuthData]:
    """getAssertion for one credential, with its signature verified."""
    client_data_hash = client_data_hash or os.urandom(32)
    allow_ids = [credential.credential_id] if allow_list else None
    response = get_assertion(ctap, credential.rp_id, client_data_hash, allow_ids, **kwargs)
    assert response[1] == {"type": "public-key", "id": credential.credential_id}
    auth_data = AuthData.parse(response[2])
    auth_data.check(credential.rp_id, up=True, uv=uv, at=False)
    verify_signature(credential.public_key, response[2] + client_data_hash, response[3])
    try:
        verify_signature(credential.public_key, response[2] + os.urandom(32), response[3])
    except InvalidSignature:
        pass
    else:
        raise AssertionError("the signature also verifies over a different client data hash")
    return response, auth_data
