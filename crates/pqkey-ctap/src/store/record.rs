//! The records a [`CredentialStore`](super::CredentialStore) persists.
//!
//! These types are deliberately independent of the CTAP engine's in-memory
//! structures: they describe exactly what is written to storage and nothing
//! else.  Every type that holds secret material zeroizes it on drop, redacts it
//! from `Debug` output, and compares it in constant time.
//!
//! Zeroizing on drop wipes a value where it finally lives.  Moving a value in
//! Rust is a bitwise copy, so the stores avoid needless moves of records (such
//! as vector reallocation) but cannot rule out every stale copy.

// A new algorithm, key kind or key type must be handled at every match on
// one: no arm may catch it unseen.
#![deny(
    clippy::wildcard_enum_match_arm,
    clippy::match_wildcard_for_single_variants
)]

use core::fmt;

use rand_core::TryCryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::credential_key::try_generate_key;
use crate::{
    CoseAlg, CredentialSecretKey, CryptoError, KeyKind, try_cose_public_key,
    try_credential_secret_from_bytes,
};

/// The private key of a credential, in its most compact form: one variant
/// per [`KeyKind`], and each algorithm keeps the kind [`CoseAlg::key_kind`]
/// names.
///
/// ML-DSA keys are kept as the 32-byte FIPS 204 key-generation seed `ξ`, not as
/// the 2,560–4,896-byte expanded secret key.  The seed determines the whole key
/// pair (FIPS 204 Algorithm 6, `ML-DSA.KeyGen_internal`, expands it),
/// so nothing is lost, and every record stays a few hundred bytes regardless of
/// the parameter set.  The price is one key expansion each time the key is
/// used, which is far cheaper than the signature it enables.  The seed is as
/// sensitive as the expanded key and gets the same protection: it is zeroized
/// on drop, redacted from `Debug`, and compared in constant time.
///
/// ECDSA keys on P-384, P-521 and secp256k1 are kept as a 32-byte seed too,
/// from which each use derives the scalar (FIPS 186-5 Appendix A.2.1), so
/// that their records hold 32 bytes of key like every other.  An EdDSA key on
/// Ed25519 is its 32-byte RFC 8032 private key, a seed by nature: random
/// bytes that each use hashes into the secret scalar (§5.1.5).  One on Ed448
/// is a 32-byte seed from which each use derives its 57-byte private key with
/// SHAKE256. RSA keeps its two 1024-bit primes, 256 bytes in total.
/// Each read reconstructs n, d and the CRT values, with e = 65537.
///
/// The public key is never stored: [`CredentialRecord::cose_public_key`]
/// derives it from this material, so a record cannot carry a public key that
/// disagrees with its secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[expect(
    clippy::large_enum_variant,
    reason = "keep the fixed RSA prime bytes inline and zeroize the entire material on drop"
)]
pub enum PrivateKeyMaterial {
    /// A P-256 private scalar, big-endian ([`KeyKind::P256Scalar`]).
    P256Scalar {
        /// The scalar.  It must be non-zero and below the P-256 group order.
        scalar: [u8; 32],
    },
    /// A seed from which the owning record's `alg` derives the key
    /// ([`KeyKind::Seed`]): for ML-DSA, the FIPS 204 key-generation seed `ξ`,
    /// which the parameter set of `alg` expands; for ECDSA on P-384, P-521
    /// and secp256k1, the seed the scalar is derived from; and for EdDSA, the
    /// RFC 8032 private key itself on Ed25519 and the seed it is derived from
    /// on Ed448.
    Seed {
        /// The seed.
        seed: [u8; 32],
    },
    /// RSA-2048 primes, with e = 65537 implicit ([`KeyKind::RsaPrimes`]).
    RsaPrimes {
        /// p || q, each prime exactly 128 big-endian bytes.
        primes: [u8; 256],
    },
}

/// The 32-byte key material that fits a sealed credential ID. Only the
/// scalar and seed variants can construct it; zeroized on drop and redacted.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SealableKeyMaterial([u8; 32]);

impl SealableKeyMaterial {
    /// The sealed ID's fixed-size private key field.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SealableKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealableKeyMaterial(<redacted>)")
    }
}

impl PrivateKeyMaterial {
    /// A copy that fits a sealed ID, if this kind of key can be sealed.
    pub(crate) fn sealable(&self) -> Option<SealableKeyMaterial> {
        match self {
            Self::P256Scalar { scalar } => Some(SealableKeyMaterial(*scalar)),
            Self::Seed { seed } => Some(SealableKeyMaterial(*seed)),
            Self::RsaPrimes { .. } => None,
        }
    }

    /// Generate fresh key material for `alg` from the operating system's
    /// random number generator, getrandom(2) on Linux.
    ///
    /// For ML-DSA this draws only the 32-byte seed `ξ`; the expensive
    /// expansion happens when the key is first used.  ECDSA on P-384, P-521
    /// and secp256k1 and EdDSA draw a seed as well.  getrandom(2) is a
    /// cryptographically secure generator, but not a random bit generator
    /// approved under NIST SP 800-90A, which FIPS 204 §3.6.1 asks a validated
    /// implementation to use for `ξ` and for hedged signing's `rnd`; that
    /// only matters for a FIPS 140 claim, which pqkey does not make.
    ///
    /// Fails with [`CryptoError::Randomness`] if the generator fails, so a
    /// registration fails instead of the process.
    pub fn try_generate(alg: CoseAlg) -> Result<Self, CryptoError> {
        Self::try_generate_from_rng(alg, &mut getrandom::SysRng)
    }

    /// [`Self::try_generate`] with `rng` as the random number generator.
    pub fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(
        alg: CoseAlg,
        rng: &mut R,
    ) -> Result<Self, CryptoError> {
        crate::crypto::scrub::with_scrubbed_stack(|| {
            let kind = alg.key_kind();
            let key = try_generate_key(kind, rng)?;
            Self::from_bytes(kind, &key)
        })
    }

    /// [`Self::try_generate`] for tests and tools that cannot go on without a
    /// key.
    ///
    /// # Panics
    ///
    /// Panics if key generation fails.
    #[must_use]
    pub fn generate(alg: CoseAlg) -> Self {
        Self::try_generate(alg).expect("credential key generation failed")
    }

    /// The kind of key material this is.
    pub fn kind(&self) -> KeyKind {
        match self {
            PrivateKeyMaterial::P256Scalar { .. } => KeyKind::P256Scalar,
            PrivateKeyMaterial::Seed { .. } => KeyKind::Seed,
            PrivateKeyMaterial::RsaPrimes { .. } => KeyKind::RsaPrimes,
        }
    }

    /// Key material of `kind` holding `bytes`.  The bytes are not checked
    /// here: an out-of-range P-256 scalar is found where a record is
    /// validated.
    pub(crate) fn from_bytes(kind: KeyKind, bytes: &[u8]) -> Result<Self, CryptoError> {
        match kind {
            KeyKind::P256Scalar => Ok(Self::P256Scalar {
                scalar: bytes.try_into().map_err(|_| CryptoError::InvalidKey)?,
            }),
            KeyKind::Seed => Ok(Self::Seed {
                seed: bytes.try_into().map_err(|_| CryptoError::InvalidKey)?,
            }),
            KeyKind::RsaPrimes => Ok(Self::RsaPrimes {
                primes: bytes.try_into().map_err(|_| CryptoError::InvalidKey)?,
            }),
        }
    }

    /// The key bytes, whatever their kind.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::P256Scalar { scalar } => scalar,
            Self::Seed { seed } => seed,
            Self::RsaPrimes { primes } => primes,
        }
    }
}

/// Constant-time with respect to the key bytes.
impl PartialEq for PrivateKeyMaterial {
    fn eq(&self, other: &Self) -> bool {
        self.kind() == other.kind() && bool::from(self.as_bytes().ct_eq(other.as_bytes()))
    }
}

impl Eq for PrivateKeyMaterial {}

/// Redacted on purpose: private keys must never reach a log sink.
impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivateKeyMaterial::P256Scalar { .. } => f
                .debug_struct("P256Scalar")
                .field("scalar", &Redacted)
                .finish(),
            PrivateKeyMaterial::Seed { .. } => {
                f.debug_struct("Seed").field("seed", &Redacted).finish()
            }
            PrivateKeyMaterial::RsaPrimes { .. } => f
                .debug_struct("RsaPrimes")
                .field("primes", &Redacted)
                .finish(),
        }
    }
}

/// The largest credential blob this store accepts (CTAP 2.3 §§6.4, 12.2).
pub(crate) const MAX_CRED_BLOB_LENGTH: usize = 32;

/// One credential: a stored one, or the credential a sealed credential ID
/// carries, which is never stored.
///
/// # Creation order
///
/// `created_at` is owned by the store.  When [`put`] inserts a credential whose
/// ID is not stored yet, the store assigns it a value greater than that of
/// every credential it currently holds, so the credential created last is
/// always first in [`list`] and two credentials never tie.  When [`put`]
/// replaces an existing credential, the stored value is kept.  In both cases
/// the value in the record passed to [`put`] is ignored; construct new records
/// with `created_at: 0`.
///
/// A sequence number is used instead of a timestamp because wall clocks can
/// step backwards and have limited resolution, and CTAP requires the
/// most-recently-created credential to be returned first.
///
/// [`put`]: super::CredentialStore::put
/// [`list`]: super::CredentialStore::list
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CredentialRecord {
    /// The credential ID the relying party uses to refer to this credential.
    /// Must not be empty.
    pub credential_id: Vec<u8>,
    /// The relying party identifier the credential is scoped to.
    pub rp_id: String,
    /// The user handle (`user.id`) supplied at registration.
    pub user_id: Vec<u8>,
    /// `user.name`, if the relying party supplied one.
    pub user_name: Option<String>,
    /// `user.displayName`, if the relying party supplied one.
    pub user_display_name: Option<String>,
    /// The COSE algorithm of the credential key.  It selects the ML-DSA
    /// parameter set, the ECDSA curve or the EdDSA curve, and must agree with
    /// the variant of `private_key`.
    #[zeroize(skip)]
    pub alg: CoseAlg,
    /// The credential's private key.
    pub private_key: PrivateKeyMaterial,
    /// The `hmac-secret` `CredRandom` used when user verification was performed.
    pub cred_random_with_uv: [u8; 32],
    /// The `hmac-secret` `CredRandom` used without user verification.
    pub cred_random_without_uv: [u8; 32],
    /// The opaque credential blob, if stored (CTAP 2.3 §12.2).
    pub cred_blob: Option<Vec<u8>>,
    /// The `credProtect` level: 1 (`userVerificationOptional`), 2
    /// (`userVerificationOptionalWithCredentialIDList`), or 3
    /// (`userVerificationRequired`).  Credentials created without the
    /// extension use 1.
    pub cred_protect: u8,
    /// The signature counter.
    pub sign_count: u32,
    /// Creation order key, assigned by the store; see the type documentation.
    pub created_at: u64,
}

impl CredentialRecord {
    /// Materialise the signing key and the CBOR-encoded COSE public key in one
    /// step.
    ///
    /// Prefer this over calling [`Self::secret_key`] and
    /// [`Self::cose_public_key`] separately when both are needed: for a
    /// P-256 key each of those derives the public key.  (A key kept as a seed
    /// is the seed itself: deriving the public key expands it into the key,
    /// and so does signing.)
    ///
    /// Returns [`CryptoError::KeyTypeMismatch`] when `alg` and the key material
    /// disagree, and [`CryptoError::InvalidKey`] for an out-of-range P-256
    /// scalar or malformed RSA primes. Records loaded from a store have
    /// already been checked for both.
    pub fn keypair(&self) -> Result<(CredentialSecretKey, Vec<u8>), CryptoError> {
        let secret = self.secret_key()?;
        let public_key = try_cose_public_key(self.alg, &secret)?;
        Ok((secret, public_key))
    }

    /// Materialise the signing key, ready for [`crate::try_sign_challenge`]
    /// with this record's `alg`.  No public key is derived: signing expands
    /// a seed itself.
    ///
    /// Errors as [`Self::keypair`] does.
    pub fn secret_key(&self) -> Result<CredentialSecretKey, CryptoError> {
        if self.private_key.kind() != self.alg.key_kind() {
            return Err(CryptoError::KeyTypeMismatch);
        }
        try_credential_secret_from_bytes(self.alg, self.private_key.as_bytes())
    }

    /// Derive the CBOR-encoded COSE_Key of the credential's public key from
    /// the private key material.
    ///
    /// Errors as [`Self::keypair`] does.
    pub fn cose_public_key(&self) -> Result<Vec<u8>, CryptoError> {
        self.keypair().map(|(_, public_key)| public_key)
    }
}

/// Public fields compare normally; secret fields compare in constant time.
impl PartialEq for CredentialRecord {
    fn eq(&self, other: &Self) -> bool {
        let blobs_equal = match (&self.cred_blob, &other.cred_blob) {
            (Some(left), Some(right)) => bool::from(left.as_slice().ct_eq(right.as_slice())),
            (None, None) => true,
            _ => false,
        };
        let secrets_equal = blobs_equal
            & (self.private_key == other.private_key)
            & bool::from(
                self.cred_random_with_uv[..].ct_eq(&other.cred_random_with_uv[..])
                    & self.cred_random_without_uv[..].ct_eq(&other.cred_random_without_uv[..]),
            );
        secrets_equal
            && self.credential_id == other.credential_id
            && self.rp_id == other.rp_id
            && self.user_id == other.user_id
            && self.user_name == other.user_name
            && self.user_display_name == other.user_display_name
            && self.alg == other.alg
            && self.cred_protect == other.cred_protect
            && self.sign_count == other.sign_count
            && self.created_at == other.created_at
    }
}

impl Eq for CredentialRecord {}

/// The private key, both `CredRandom` values and credential blob are redacted.
impl fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("credential_id", &Hex(&self.credential_id))
            .field("rp_id", &self.rp_id)
            .field("user_id", &Hex(&self.user_id))
            .field("user_name", &self.user_name)
            .field("user_display_name", &self.user_display_name)
            .field("alg", &self.alg)
            .field("private_key", &self.private_key)
            .field("cred_random_with_uv", &Redacted)
            .field("cred_random_without_uv", &Redacted)
            .field("cred_blob", &Redacted)
            .field("cred_protect", &self.cred_protect)
            .field("sign_count", &self.sign_count)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// The persistent PIN state and user-verification settings.
///
/// The PIN hash, retry budget, PIN policy and always-UV setting are replaced
/// together in one write. Volatile PIN/UV auth tokens are not stored.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinStateRecord {
    /// `LEFT(SHA-256(PIN), 16)`, or `None` when no PIN is set.
    pub pin_hash: Option<[u8; 16]>,
    /// Remaining PIN attempts before the authenticator blocks the PIN.
    pub pin_retries: u8,
    /// Consecutive failed attempts since the last power cycle.
    pub consecutive_failures: u8,
    /// Whether PIN use is blocked until the authenticator is power-cycled.
    pub pin_auth_blocked: bool,
    /// The minimum PIN length in Unicode code points (CTAP 2.3 §7.4).
    pub min_pin_length: u8,
    /// RP IDs authorized to receive the `minPinLength` extension output.
    pub min_pin_length_rp_ids: Vec<String>,
    /// Whether the current PIN must be replaced before issuing a token.
    pub force_pin_change: bool,
    /// The stored PIN's Unicode code-point length; legacy records use 4.
    pub pin_code_point_length: u8,
    /// Whether registration and sign-in with user presence require UV.
    pub always_uv: bool,
}

impl PinStateRecord {
    /// The retry budget of a fresh authenticator.  CTAP 2.1 caps the PIN retry
    /// counter at 8, and the CTAP engine starts there.
    pub const MAX_PIN_RETRIES: u8 = 8;
    /// The default minimum PIN length, restored only by a reset.
    pub const DEFAULT_MIN_PIN_LENGTH: u8 = 4;
    /// The largest PIN length the authenticator can require.
    pub const MAX_PIN_LENGTH: u8 = 63;
    /// The number of RP IDs the `minPinLength` policy can store.
    pub const MAX_MIN_PIN_LENGTH_RP_IDS: usize = 8;
    /// The largest stored RP ID, in UTF-8 bytes.
    pub const MAX_RP_ID_LENGTH: usize = 253;
}

/// No PIN set, full retry budget, not blocked: the state after a reset.
impl Default for PinStateRecord {
    fn default() -> Self {
        Self {
            pin_hash: None,
            pin_retries: Self::MAX_PIN_RETRIES,
            consecutive_failures: 0,
            pin_auth_blocked: false,
            min_pin_length: Self::DEFAULT_MIN_PIN_LENGTH,
            min_pin_length_rp_ids: Vec::new(),
            force_pin_change: false,
            pin_code_point_length: Self::DEFAULT_MIN_PIN_LENGTH,
            always_uv: false,
        }
    }
}

/// The PIN hash compares in constant time.
impl PartialEq for PinStateRecord {
    fn eq(&self, other: &Self) -> bool {
        let hashes_equal = match (&self.pin_hash, &other.pin_hash) {
            (Some(a), Some(b)) => bool::from(a[..].ct_eq(&b[..])),
            (None, None) => true,
            _ => false,
        };
        hashes_equal
            && self.pin_retries == other.pin_retries
            && self.consecutive_failures == other.consecutive_failures
            && self.pin_auth_blocked == other.pin_auth_blocked
            && self.min_pin_length == other.min_pin_length
            && self.min_pin_length_rp_ids == other.min_pin_length_rp_ids
            && self.force_pin_change == other.force_pin_change
            && self.pin_code_point_length == other.pin_code_point_length
            && self.always_uv == other.always_uv
    }
}

impl Eq for PinStateRecord {}

/// The PIN hash is redacted; only whether a PIN is set is shown.
impl fmt::Debug for PinStateRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinStateRecord")
            .field("pin_hash", &self.pin_hash.as_ref().map(|_| Redacted))
            .field("pin_retries", &self.pin_retries)
            .field("consecutive_failures", &self.consecutive_failures)
            .field("pin_auth_blocked", &self.pin_auth_blocked)
            .field("min_pin_length", &self.min_pin_length)
            .field("min_pin_length_rp_ids", &self.min_pin_length_rp_ids)
            .field("force_pin_change", &self.force_pin_change)
            .field("pin_code_point_length", &self.pin_code_point_length)
            .field("always_uv", &self.always_uv)
            .finish()
    }
}

/// The authenticator's batch attestation key and certificate chain.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AttestationRecord {
    /// The P-256 attestation private scalar, big-endian.  It must be non-zero
    /// and below the group order.
    pub private_key: [u8; 32],
    /// DER-encoded X.509 certificates, attestation certificate first.  Must
    /// contain at least one certificate, and no certificate may be empty.
    pub certificate_chain: Vec<Vec<u8>>,
}

impl AttestationRecord {
    /// Materialise the attestation signing key, an ES256 key read as a
    /// credential's is ([`try_credential_secret_from_bytes`]): on a scrubbed
    /// stack, since reading it multiplies the base point by the scalar.
    ///
    /// Returns [`CryptoError::InvalidKey`] for an out-of-range scalar.
    pub fn signing_key(&self) -> Result<CredentialSecretKey, CryptoError> {
        try_credential_secret_from_bytes(CoseAlg::ES256, &self.private_key)
    }
}

/// The private key compares in constant time.
impl PartialEq for AttestationRecord {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.private_key[..].ct_eq(&other.private_key[..]))
            && self.certificate_chain == other.certificate_chain
    }
}

impl Eq for AttestationRecord {}

/// The private key is redacted.
impl fmt::Debug for AttestationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationRecord")
            .field("private_key", &Redacted)
            .field(
                "certificate_chain",
                &self
                    .certificate_chain
                    .iter()
                    .map(|certificate| CertificateSummary(certificate.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Renders as `<redacted>`.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Renders a byte string as lowercase hex.
struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Renders a certificate as its length only.
struct CertificateSummary(usize);

impl fmt::Debug for CertificateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::alg::Scheme;
    use crate::crypto::ecdsa::{self, Curve};
    use crate::crypto::eddsa::{self, EdwardsCurve};
    use crate::crypto::mldsa;
    use crate::crypto::verify::verify_signature;
    use crate::try_sign_challenge;
    use p256::ecdsa::{Signature, SigningKey as P256SigningKey, signature::Verifier};
    use pqkey_mldsa::try_keypair_from_seed;

    /// A random number generator that always fails.
    struct FailingRng;

    #[derive(Debug)]
    struct NoRandomness;

    impl fmt::Display for NoRandomness {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("no randomness")
        }
    }

    impl core::error::Error for NoRandomness {}

    impl rand_core::TryRng for FailingRng {
        type Error = NoRandomness;
        fn try_next_u32(&mut self) -> Result<u32, NoRandomness> {
            Err(NoRandomness)
        }
        fn try_next_u64(&mut self) -> Result<u64, NoRandomness> {
            Err(NoRandomness)
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), NoRandomness> {
            Err(NoRandomness)
        }
    }

    impl TryCryptoRng for FailingRng {}

    /// A failing generator is reported, never a panic or a key of zeros.
    #[test]
    fn key_generation_reports_a_failing_generator() {
        for alg in CoseAlg::ALL {
            assert!(
                PrivateKeyMaterial::try_generate_from_rng(alg, &mut FailingRng).is_err(),
                "{alg:?}"
            );
            assert!(PrivateKeyMaterial::try_generate(alg).is_ok(), "{alg:?}");
        }
    }

    fn record(alg: CoseAlg) -> CredentialRecord {
        CredentialRecord {
            credential_id: vec![0x11; 32],
            rp_id: "example.com".into(),
            user_id: vec![0x22; 16],
            user_name: Some("alice".into()),
            user_display_name: Some("Alice".into()),
            alg,
            private_key: PrivateKeyMaterial::generate(alg),
            cred_random_with_uv: [0x33; 32],
            cred_random_without_uv: [0x44; 32],
            cred_blob: None,
            cred_protect: 1,
            sign_count: 7,
            created_at: 0,
        }
    }

    /// Sign with the materialised key and verify with the derived public key,
    /// using the test verifier, which does not go through the record helpers.
    fn assert_signature_verifies(record: &CredentialRecord) {
        let (secret, cose) = record.keypair().expect("materialise key pair");
        let auth_data = b"authenticator data";
        let client_data_hash = [0x5a; 32];
        let signature = try_sign_challenge(record.alg, &secret, auth_data, &client_data_hash)
            .expect("sign challenge");
        let mut message = auth_data.to_vec();
        message.extend_from_slice(&client_data_hash);
        verify_signature(record.alg, &cose, &message, &signature)
            .expect("the signature verifies under the derived public key");
    }

    #[test]
    fn generated_material_matches_its_algorithm() {
        for alg in CoseAlg::ALL {
            let material = PrivateKeyMaterial::generate(alg);
            assert_eq!(material.kind(), alg.key_kind(), "{alg:?}");
            for other in CoseAlg::ALL {
                let p256 = |alg| matches!(alg, CoseAlg::ES256 | CoseAlg::ESP256);
                let rsa = |alg| {
                    matches!(
                        alg,
                        CoseAlg::RS256
                            | CoseAlg::RS384
                            | CoseAlg::RS512
                            | CoseAlg::PS256
                            | CoseAlg::PS384
                            | CoseAlg::PS512
                    )
                };
                let same_family = p256(alg) == p256(other) && rsa(alg) == rsa(other);
                assert_eq!(
                    material.kind() == other.key_kind(),
                    same_family,
                    "{alg:?} vs {other:?}"
                );
            }
            match &material {
                PrivateKeyMaterial::P256Scalar { scalar } => {
                    assert!(p256::SecretKey::from_slice(scalar).is_ok());
                }
                PrivateKeyMaterial::Seed { .. } => {}
                PrivateKeyMaterial::RsaPrimes { primes } => {
                    assert!(crate::crypto::rsa::signing_key(primes).is_ok());
                }
            }
        }
        assert_ne!(
            PrivateKeyMaterial::generate(CoseAlg::MLDSA44),
            PrivateKeyMaterial::generate(CoseAlg::MLDSA44),
            "seeds must be random"
        );
    }

    #[test]
    fn every_algorithm_signs_and_verifies_with_the_derived_public_key() {
        for alg in CoseAlg::ALL {
            assert_signature_verifies(&record(alg));
        }
    }

    #[test]
    fn helpers_agree_and_are_deterministic() {
        for alg in CoseAlg::ALL {
            let record = record(alg);
            let (_, from_keypair) = record.keypair().unwrap();
            assert_eq!(record.cose_public_key().unwrap(), from_keypair, "{alg:?}");
            assert_eq!(record.cose_public_key().unwrap(), from_keypair, "{alg:?}");
            assert!(record.secret_key().is_ok());
        }
    }

    /// The stored seed is FIPS 204 `ξ` itself, not some wrapped form of it.
    #[test]
    fn mldsa_material_is_the_fips204_seed() {
        for alg in CoseAlg::ALL {
            let param_set = match alg.scheme() {
                Scheme::MlDsa(param_set) => param_set,
                Scheme::Ecdsa(_) | Scheme::EdDsa(_) | Scheme::Rsa(_, _) => continue,
            };
            let record = record(alg);
            let PrivateKeyMaterial::Seed { seed } = &record.private_key else {
                panic!("ML-DSA record must hold a seed");
            };
            let (public_key, _) = try_keypair_from_seed(param_set, seed).unwrap();
            let expected = mldsa::try_cose_key(alg, &public_key).unwrap();
            assert_eq!(record.cose_public_key().unwrap(), expected, "{alg:?}");
        }
    }

    /// The stored seed of an EdDSA key is its RFC 8032 private key itself,
    /// from which nothing is derived before RFC 8032 hashes it.
    #[test]
    fn eddsa_material_is_the_rfc_8032_private_key() {
        let record = record(CoseAlg::EdDSA);
        let PrivateKeyMaterial::Seed { seed } = &record.private_key else {
            panic!("an EdDSA record must hold a seed");
        };
        let public_key = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key();
        assert_eq!(
            record.cose_public_key().unwrap(),
            eddsa::try_cose_key(CoseAlg::EdDSA, EdwardsCurve::Ed25519, public_key.as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn es256_material_is_the_raw_scalar() {
        let record = record(CoseAlg::ES256);
        let PrivateKeyMaterial::P256Scalar { scalar } = &record.private_key else {
            panic!("ES256 record must hold a scalar");
        };
        let signing_key = P256SigningKey::from_slice(scalar).unwrap();
        let point = signing_key.verifying_key().to_sec1_point(false);
        assert_eq!(
            record.cose_public_key().unwrap(),
            ecdsa::try_cose_key(CoseAlg::ES256, Curve::P256, point.coordinates()).unwrap()
        );
    }

    #[test]
    fn mismatched_algorithm_and_material_is_rejected() {
        let mut es256_alg_with_seed = record(CoseAlg::MLDSA65);
        es256_alg_with_seed.alg = CoseAlg::ES256;
        let mut mldsa_alg_with_scalar = record(CoseAlg::ES256);
        mldsa_alg_with_scalar.alg = CoseAlg::MLDSA87;
        for record in [&es256_alg_with_seed, &mldsa_alg_with_scalar] {
            assert_eq!(record.keypair().err(), Some(CryptoError::KeyTypeMismatch));
            assert_eq!(
                record.cose_public_key().err(),
                Some(CryptoError::KeyTypeMismatch)
            );
            assert!(matches!(
                record.secret_key(),
                Err(CryptoError::KeyTypeMismatch)
            ));
        }
    }

    #[test]
    fn out_of_range_es256_scalar_is_rejected() {
        for scalar in [[0u8; 32], [0xff; 32]] {
            let mut record = record(CoseAlg::ES256);
            record.private_key = PrivateKeyMaterial::P256Scalar { scalar };
            assert_eq!(record.keypair().err(), Some(CryptoError::InvalidKey));
        }
    }

    #[test]
    fn equality_covers_secret_and_public_fields() {
        let original = record(CoseAlg::MLDSA44);
        assert_eq!(original, original.clone());

        let mut changed = original.clone();
        changed.private_key = PrivateKeyMaterial::generate(CoseAlg::MLDSA44);
        assert_ne!(original, changed);

        let mut changed = original.clone();
        changed.cred_random_with_uv[31] ^= 1;
        assert_ne!(original, changed);

        let mut changed = original.clone();
        changed.cred_random_without_uv[0] ^= 1;
        assert_ne!(original, changed);

        let mut changed = original.clone();
        changed.sign_count += 1;
        assert_ne!(original, changed);

        let mut changed = original.clone();
        changed.user_display_name = None;
        assert_ne!(original, changed);

        let mut changed = original.clone();
        changed.cred_blob = Some(Vec::new());
        assert_ne!(original, changed, "absent and empty differ");
        let mut with_blob = original.clone();
        with_blob.cred_blob = Some(vec![0x55; 32]);
        changed.cred_blob = Some(vec![0x55; 31]);
        assert_ne!(with_blob, changed);
        changed.cred_blob = Some(vec![0x55; 32]);
        assert_eq!(with_blob, changed);
        changed.cred_blob.as_mut().unwrap()[31] ^= 1;
        assert_ne!(with_blob, changed);
        changed.zeroize();
        assert!(changed.cred_blob.is_none());

        let es256 = PrivateKeyMaterial::P256Scalar { scalar: [1; 32] };
        let mldsa = PrivateKeyMaterial::Seed { seed: [1; 32] };
        assert_ne!(es256, mldsa, "same bytes, different key types");
    }

    /// No rendering of any secret byte may appear in `Debug` output.
    #[test]
    fn debug_output_redacts_secrets() {
        let secret = 0xc7u8; // renders as "c7" in hex and "199" in decimal
        let record = CredentialRecord {
            credential_id: vec![0x01, 0x02],
            rp_id: "example.com".into(),
            user_id: vec![0x03],
            user_name: None,
            user_display_name: None,
            alg: CoseAlg::ES256,
            private_key: PrivateKeyMaterial::P256Scalar {
                scalar: [secret; 32],
            },
            cred_random_with_uv: [secret; 32],
            cred_random_without_uv: [secret; 32],
            cred_blob: Some(vec![secret; 32]),
            cred_protect: 2,
            sign_count: 5,
            created_at: 9,
        };
        let pin = PinStateRecord {
            pin_hash: Some([secret; 16]),
            min_pin_length_rp_ids: Vec::new(),
            ..PinStateRecord::default()
        };
        let attestation = AttestationRecord {
            private_key: [secret; 32],
            certificate_chain: vec![vec![0x30, 0x82]],
        };
        for rendered in [
            format!("{record:?}"),
            format!("{record:#?}"),
            format!("{:?}", record.private_key),
            format!("{pin:?}"),
            format!("{attestation:?}"),
        ] {
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(!rendered.contains("c7"), "{rendered}");
            assert!(!rendered.contains("C7"), "{rendered}");
            assert!(!rendered.contains("199"), "{rendered}");
        }
        assert!(format!("{record:?}").contains("0102"), "IDs render as hex");
        assert!(format!("{attestation:?}").contains("<2 bytes>"));
    }

    #[test]
    fn default_pin_state_is_a_fresh_authenticator() {
        let state = PinStateRecord::default();
        assert_eq!(state.pin_hash, None);
        assert_eq!(state.pin_retries, 8);
        assert_eq!(state.consecutive_failures, 0);
        assert!(!state.pin_auth_blocked);
    }

    #[test]
    fn pin_state_equality_compares_the_hash() {
        let a = PinStateRecord {
            pin_hash: Some([1; 16]),
            min_pin_length_rp_ids: Vec::new(),
            ..PinStateRecord::default()
        };
        let mut b = a.clone();
        assert_eq!(a, b);
        b.pin_hash = Some([2; 16]);
        assert_ne!(a, b);
        b.pin_hash = None;
        assert_ne!(a, b);
    }

    #[test]
    fn attestation_signing_key_checks_the_scalar() {
        let valid = AttestationRecord {
            private_key: [0x42; 32],
            certificate_chain: vec![vec![0x30]],
        };
        let CredentialSecretKey::P256(signing_key) = valid.signing_key().expect("valid scalar")
        else {
            panic!("the attestation key is a P-256 key");
        };
        let signature: Signature = p256::ecdsa::signature::Signer::sign(&signing_key, b"msg");
        signing_key
            .verifying_key()
            .verify(b"msg", &signature)
            .unwrap();

        let invalid = AttestationRecord {
            private_key: [0; 32],
            certificate_chain: vec![vec![0x30]],
        };
        assert_eq!(invalid.signing_key().err(), Some(CryptoError::InvalidKey));
    }
}
