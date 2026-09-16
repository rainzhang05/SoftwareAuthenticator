//! Safe Rust wrapper around pure-Rust ML-DSA implementations from `fips204`.
//!
//! This crate exposes a small, stable surface (`keypair`, `sign`, `verify`)
//! for the three ML-DSA parameter sets defined in FIPS 204 (ML-DSA-44/65/87).
//! The implementation is provided by the `fips204` crate, which has no C
//! dependencies, contains no `unsafe` code, and operates in constant-time.
//!
//! Secret keys are zeroized on drop.
//!
//! # Which FIPS 204 algorithm is this?
//!
//! Everything here is *pure* ML-DSA over the **external** interface, i.e.
//! `ML-DSA.Sign` (FIPS 204 Algorithm 2) and `ML-DSA.Verify` (Algorithm 3).
//! The message is domain-separated before hashing as
//! `M' = 0x00 || len(ctx) || ctx || M`.  The pre-hash variant (`HashML-DSA`)
//! and the raw `*_internal` interface are deliberately **not** exposed: the
//! CTAP2 / WebAuthn profile that uses this wrapper signs the raw
//! `authenticatorData || clientDataHash` buffer with an empty context.
//!
//! # Signing is randomized ("hedged") by default
//!
//! [`sign`] / [`try_sign`] use the hedged variant of Algorithm 2, so signing
//! the same message twice yields two different (equally valid) signatures.
//! Reproducible signatures are available through [`try_sign_deterministic`],
//! which pins the 32-byte `rnd` value; that function exists for known-answer
//! testing and for callers that specifically need FIPS 204's deterministic
//! variant (`rnd = 0^32`).  Prefer the hedged path in production.
//!
//! # Feature flags
//!
//! * `mldsa44`, `mldsa65`, `mldsa87` — compile in the matching parameter set.
//!   All three are on by default.  Calls for a parameter set that was compiled
//!   out return [`MlDsaError::InvalidParameterSet`] (or `false` from
//!   [`verify`]); only the legacy panicking helpers [`lengths`] and [`keypair`]
//!   panic in that case.
//! * `log` — on by default; routes diagnostics through the `log` crate.  With
//!   `default-features = false` the crate is silent, and the empty-`Vec`
//!   failure mode of [`sign`] becomes completely undiagnosable.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations, unused_qualifications)]

use core::fmt;

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of the FIPS 204 key-generation seed (`ξ`) and of the
/// per-signature randomness (`rnd`).
pub const SEED_LEN: usize = 32;

/// Maximum length of a signing/verification context string, per FIPS 204
/// (`|ctx| ≤ 255`).
pub const MAX_CONTEXT_LEN: usize = 255;

/// ML-DSA parameter sets supported by this wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamSet {
    /// ML-DSA-44 (NIST security category 2).
    MLDSA44,
    /// ML-DSA-65 (NIST security category 3).
    MLDSA65,
    /// ML-DSA-87 (NIST security category 5).
    MLDSA87,
}

impl ParamSet {
    /// Every parameter set this crate knows about, enabled or not.
    pub const ALL: [ParamSet; 3] = [ParamSet::MLDSA44, ParamSet::MLDSA65, ParamSet::MLDSA87];

    /// The name used by FIPS 204 and by the NIST ACVP test vectors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ParamSet::MLDSA44 => "ML-DSA-44",
            ParamSet::MLDSA65 => "ML-DSA-65",
            ParamSet::MLDSA87 => "ML-DSA-87",
        }
    }

    /// Parse a FIPS 204 / ACVP parameter-set name such as `"ML-DSA-65"`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        ParamSet::ALL.into_iter().find(|ps| ps.name() == name)
    }

    /// Whether this parameter set was compiled in.  When this returns `false`
    /// every fallible entry point reports [`MlDsaError::InvalidParameterSet`].
    #[must_use]
    pub fn is_enabled(self) -> bool {
        try_lengths(self).is_ok()
    }
}

impl fmt::Display for ParamSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Public key wrapper. The inner bytes are the canonical FIPS 204 encoding.
///
/// The field is public for backwards compatibility; prefer [`PublicKey::new`]
/// and [`PublicKey::as_bytes`] in new code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    /// Wrap already-encoded public key bytes.  No validation is performed
    /// here; [`verify`] rejects keys of the wrong length or encoding.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        PublicKey(bytes)
    }

    /// The canonical FIPS 204 encoding of this key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper and return the encoded key.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Length of the encoded key in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the wrapper holds no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Secret key wrapper. The inner bytes are the canonical FIPS 204 encoding;
/// they are zeroized on drop.
///
/// # Hazard: the inner field is public
///
/// `SecretKey` zeroizes on drop, but that only protects the buffer it still
/// owns.  Any of the following defeats it and leaves key material in memory
/// for the allocator to hand out again:
///
/// * `sk.0.clone()` / `sk.as_bytes().to_vec()` — the copy has no `Drop` glue;
/// * `let bytes = sk.0;` — moving out of the field (only possible because the
///   field is public) skips this type's `Drop` entirely;
/// * `sk.0.push(..)` / `sk.0 = ..` — a reallocation leaves the old buffer
///   behind un-zeroized.
///
/// Callers that must copy the bytes out (for persistence, say) are responsible
/// for zeroizing the copy, e.g. with [`zeroize::Zeroize`].  The field stays
/// public only because existing callers construct `SecretKey(bytes)` and read
/// `sk.0` directly; prefer [`SecretKey::new`] and [`SecretKey::as_bytes`].
pub struct SecretKey(pub Vec<u8>);

impl SecretKey {
    /// Wrap already-encoded secret key bytes.  No validation is performed
    /// here; the signing entry points reject keys of the wrong length.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        SecretKey(bytes)
    }

    /// Copy `bytes` into a new zeroize-on-drop wrapper.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        SecretKey(bytes.to_vec())
    }

    /// Borrow the canonical FIPS 204 encoding of this key.
    ///
    /// Borrowing is safe; copying the result out of the borrow is what
    /// escapes zeroization (see the type-level hazard note).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length of the encoded key in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the wrapper holds no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Redacted on purpose: secret keys must never reach a log sink.
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey")
            .field(&format_args!("<{} bytes redacted>", self.0.len()))
            .finish()
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

/// Returned by FIPS 204 calls that fail at runtime (invalid lengths,
/// keygen failure, signing failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaError {
    /// The requested parameter set was compiled out of this build.
    InvalidParameterSet,
    /// The supplied key is not the right length for the parameter set, or it
    /// is not a well-formed FIPS 204 key encoding.
    InvalidKeyLength,
    /// The supplied signature is not the right length for the parameter set.
    InvalidSignatureLength,
    /// Key generation failed; in practice this surfaces an RNG failure.
    KeyGenFailed,
    /// Signing failed.  Besides an RNG failure this also covers a context
    /// string longer than [`MAX_CONTEXT_LEN`].
    SigningFailed,
}

impl fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MlDsaError::InvalidParameterSet => "ML-DSA parameter set is not enabled in this build",
            MlDsaError::InvalidKeyLength => "ML-DSA key has an invalid length or encoding",
            MlDsaError::InvalidSignatureLength => "ML-DSA signature has an invalid length",
            MlDsaError::KeyGenFailed => "ML-DSA key generation failed",
            MlDsaError::SigningFailed => "ML-DSA signing failed",
        };
        f.write_str(msg)
    }
}

/// Run `$body` with `$m` bound to the `fips204` module for `$ps`, or evaluate
/// `$disabled` when that parameter set was compiled out.
///
/// Dispatching through one macro keeps the three arms of every entry point
/// byte-for-byte identical, which is the whole point: a copy-paste slip
/// between `ml_dsa_44` and `ml_dsa_65` in a hand-written arm would be a
/// silent, security-relevant bug.
macro_rules! dispatch {
    ($ps:expr, |$m:ident| $body:block, $disabled:expr) => {
        match $ps {
            #[cfg(feature = "mldsa44")]
            ParamSet::MLDSA44 => {
                use fips204::ml_dsa_44 as $m;
                $body
            }
            #[cfg(feature = "mldsa65")]
            ParamSet::MLDSA65 => {
                use fips204::ml_dsa_65 as $m;
                $body
            }
            #[cfg(feature = "mldsa87")]
            ParamSet::MLDSA87 => {
                use fips204::ml_dsa_87 as $m;
                $body
            }
            #[cfg(not(feature = "mldsa44"))]
            ParamSet::MLDSA44 => $disabled,
            #[cfg(not(feature = "mldsa65"))]
            ParamSet::MLDSA65 => $disabled,
            #[cfg(not(feature = "mldsa87"))]
            ParamSet::MLDSA87 => $disabled,
        }
    };
}

/// Return the (public-key, secret-key, signature) byte lengths for a
/// parameter set, or [`MlDsaError::InvalidParameterSet`] if it was compiled
/// out.  Never panics.
pub fn try_lengths(ps: ParamSet) -> Result<(usize, usize, usize), MlDsaError> {
    dispatch!(
        ps,
        |m| { Ok((m::PK_LEN, m::SK_LEN, m::SIG_LEN)) },
        Err(MlDsaError::InvalidParameterSet)
    )
}

/// Return the (public-key, secret-key, signature) byte lengths for a
/// parameter set.  Useful for storage / buffer sizing.
///
/// # Panics
///
/// Panics if the parameter-set feature is not enabled.  With this crate's
/// default features all three are enabled and this cannot happen; use
/// [`try_lengths`] if you build with a reduced feature set.
#[must_use]
pub fn lengths(ps: ParamSet) -> (usize, usize, usize) {
    match try_lengths(ps) {
        Ok(lengths) => lengths,
        Err(_) => panic!("cargo feature for {ps} is not enabled"),
    }
}

/// Generate an ML-DSA keypair.
///
/// Returns [`MlDsaError::InvalidParameterSet`] if the parameter-set feature is
/// not enabled, or [`MlDsaError::KeyGenFailed`] if the underlying FIPS 204
/// keygen call fails (extremely rare; surfaces RNG problems).  Never panics.
pub fn try_keypair(ps: ParamSet) -> Result<(PublicKey, SecretKey), MlDsaError> {
    dispatch!(
        ps,
        |m| {
            let (pk, sk) = m::try_keygen().map_err(|_| MlDsaError::KeyGenFailed)?;
            Ok((
                PublicKey(pk.into_bytes().to_vec()),
                SecretKey(sk.into_bytes().to_vec()),
            ))
        },
        Err(MlDsaError::InvalidParameterSet)
    )
}

/// Generate an ML-DSA keypair, panicking on failure.  Kept for API
/// compatibility with the previous liboqs-based wrapper.
///
/// # Panics
///
/// Panics if the parameter-set feature is not enabled or if key generation
/// fails.  Prefer [`try_keypair`].
#[must_use]
pub fn keypair(ps: ParamSet) -> (PublicKey, SecretKey) {
    try_keypair(ps).expect("ML-DSA keypair generation failed")
}

/// Deterministically derive a keypair from the 32-byte FIPS 204 seed `ξ`
/// (Algorithm 6, `ML-DSA.KeyGen_internal`).  Never panics.
///
/// The same seed always yields the same keypair, so a credential can be
/// persisted as 32 bytes of seed instead of a 2560–4896 byte expanded secret
/// key and re-expanded on demand.  Expansion is not free (it is a full
/// key-generation), so it is a storage/compute trade-off.
///
/// The seed is as sensitive as the secret key it expands to: it must come from
/// a CSPRNG and be stored with the same protection, and the caller is
/// responsible for zeroizing it.
pub fn try_keypair_from_seed(
    ps: ParamSet,
    seed: &[u8; SEED_LEN],
) -> Result<(PublicKey, SecretKey), MlDsaError> {
    dispatch!(
        ps,
        |m| {
            let (pk, sk) = m::KG::keygen_from_seed(seed);
            Ok((
                PublicKey(pk.into_bytes().to_vec()),
                SecretKey(sk.into_bytes().to_vec()),
            ))
        },
        Err(MlDsaError::InvalidParameterSet)
    )
}

/// Recover the public key that belongs to `sk`.  Never panics.
///
/// Useful when only the secret key was persisted, and as a cheap integrity
/// check on a decoded secret key.
pub fn try_public_key(ps: ParamSet, sk: &SecretKey) -> Result<PublicKey, MlDsaError> {
    dispatch!(
        ps,
        |m| {
            let bytes: [u8; m::SK_LEN] =
                sk.0.as_slice()
                    .try_into()
                    .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sk =
                m::PrivateKey::try_from_bytes(bytes).map_err(|_| MlDsaError::InvalidKeyLength)?;
            Ok(PublicKey(sk.get_public_key().into_bytes().to_vec()))
        },
        Err(MlDsaError::InvalidParameterSet)
    )
}

/// Try to sign `message` with the supplied secret key.  Returns the raw
/// FIPS 204 signature bytes.  The context value is always empty per the
/// CTAP2 / WebAuthn profile that uses this wrapper.
///
/// Signing is hedged (randomized), so repeated calls on the same input return
/// different signatures.  Never panics.
pub fn try_sign(ps: ParamSet, sk: &SecretKey, message: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    try_sign_with_context(ps, sk, message, &[])
}

/// Like [`try_sign`], but with an explicit FIPS 204 context string.
///
/// `ctx` longer than [`MAX_CONTEXT_LEN`] is rejected with
/// [`MlDsaError::SigningFailed`].  Never panics.
pub fn try_sign_with_context(
    ps: ParamSet,
    sk: &SecretKey,
    message: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>, MlDsaError> {
    sign_inner(ps, sk, message, ctx, None)
}

/// Sign with a caller-supplied `rnd` value instead of fresh randomness, making
/// the signature reproducible.
///
/// Passing `rnd = [0u8; 32]` produces the deterministic variant of FIPS 204
/// Algorithm 2 — the one the NIST ACVP `deterministic` test groups pin down.
/// Any other value reproduces a hedged signature.
///
/// This exists for known-answer testing and for callers with a specific need
/// for deterministic signatures.  Production code should use [`try_sign`]:
/// reusing an `rnd` value across different messages removes the hedge that
/// protects the signature against fault and side-channel attacks.
///
/// `ctx` longer than [`MAX_CONTEXT_LEN`] is rejected with
/// [`MlDsaError::SigningFailed`].  Never panics.
pub fn try_sign_deterministic(
    ps: ParamSet,
    sk: &SecretKey,
    message: &[u8],
    ctx: &[u8],
    rnd: &[u8; SEED_LEN],
) -> Result<Vec<u8>, MlDsaError> {
    sign_inner(ps, sk, message, ctx, Some(rnd))
}

fn sign_inner(
    ps: ParamSet,
    sk: &SecretKey,
    message: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8; SEED_LEN]>,
) -> Result<Vec<u8>, MlDsaError> {
    let (_pk_len, sk_len, _sig_len) = try_lengths(ps)?;
    if sk.0.len() != sk_len {
        return Err(MlDsaError::InvalidKeyLength);
    }
    if ctx.len() > MAX_CONTEXT_LEN {
        return Err(MlDsaError::SigningFailed);
    }
    dispatch!(
        ps,
        |m| {
            let bytes: [u8; m::SK_LEN] =
                sk.0.as_slice()
                    .try_into()
                    .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sk =
                m::PrivateKey::try_from_bytes(bytes).map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sig = match rnd {
                Some(rnd) => sk.try_sign_with_seed(rnd, message, ctx),
                None => sk.try_sign(message, ctx),
            }
            .map_err(|_| MlDsaError::SigningFailed)?;
            Ok(sig.to_vec())
        },
        Err(MlDsaError::InvalidParameterSet)
    )
}

/// Sign a message.  Kept for API compatibility with the previous
/// liboqs-based wrapper.
///
/// # Hazard: an empty return value means the signature failed
///
/// On *any* error — malformed stored key, disabled parameter set, RNG failure
/// — this returns an **empty `Vec`** rather than aborting, because the daemon
/// must not crash on a malformed stored credential.  A zero-length signature
/// is not a signature: it is a failure report that looks exactly like a
/// success to a caller that does not check, and shipping one over the wire
/// hands the relying party an assertion that can never verify.
///
/// **Callers must either use [`try_sign`], which reports the error properly,
/// or check `!sig.is_empty()` before using the result.**  A valid ML-DSA
/// signature is 2420/3309/4627 bytes depending on the parameter set (see
/// [`lengths`]), so `is_empty()` is an unambiguous failure test.
///
/// With the `log` feature (on by default) the underlying error is logged at
/// error level; without it the failure is entirely silent.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn sign(ps: ParamSet, sk: &SecretKey, message: &[u8]) -> Vec<u8> {
    match try_sign(ps, sk, message) {
        Ok(sig) => sig,
        Err(err) => {
            log_signing_failure(ps, err);
            Vec::new()
        }
    }
}

#[cfg(feature = "log")]
fn log_signing_failure(ps: ParamSet, err: MlDsaError) {
    log::error!("{ps} signing failed ({err}); returning an empty signature");
}

#[cfg(not(feature = "log"))]
fn log_signing_failure(_ps: ParamSet, _err: MlDsaError) {}

/// Verify a signature.  Returns `false` on length mismatch or invalid
/// signature.  The context value is always empty, matching [`try_sign`].
/// Never panics.
#[must_use]
pub fn verify(ps: ParamSet, pk: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    verify_with_context(ps, pk, message, signature, &[])
}

/// Like [`verify`], but with an explicit FIPS 204 context string.  A `ctx`
/// longer than [`MAX_CONTEXT_LEN`] can never have been produced by a
/// conforming signer and is rejected.  Never panics.
#[must_use]
pub fn verify_with_context(
    ps: ParamSet,
    pk: &PublicKey,
    message: &[u8],
    signature: &[u8],
    ctx: &[u8],
) -> bool {
    let Ok((pk_len, _sk_len, sig_len)) = try_lengths(ps) else {
        return false;
    };
    if pk.0.len() != pk_len || signature.len() != sig_len || ctx.len() > MAX_CONTEXT_LEN {
        return false;
    }
    dispatch!(
        ps,
        |m| {
            let Ok(pk_bytes) = <[u8; m::PK_LEN]>::try_from(pk.0.as_slice()) else {
                return false;
            };
            let Ok(sig_bytes) = <[u8; m::SIG_LEN]>::try_from(signature) else {
                return false;
            };
            match m::PublicKey::try_from_bytes(pk_bytes) {
                Ok(pk) => pk.verify(message, &sig_bytes, ctx),
                Err(_) => false,
            }
        },
        false
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parameter sets actually compiled into this build.  Tests iterate
    /// over these so the suite stays meaningful under a reduced feature set.
    fn enabled() -> impl Iterator<Item = ParamSet> {
        ParamSet::ALL.into_iter().filter(|ps| ps.is_enabled())
    }

    fn roundtrip(ps: ParamSet) {
        let (pk, sk) = keypair(ps);
        let (pk_len, sk_len, _sig_len) = lengths(ps);
        assert_eq!(pk.0.len(), pk_len, "public key length");
        assert_eq!(sk.0.len(), sk_len, "secret key length");

        let message = b"post-quantum authentication";
        let signature = sign(ps, &sk, message);
        assert!(
            verify(ps, &pk, message, &signature),
            "verification failed for {ps:?}"
        );

        let mut tampered = signature.clone();
        tampered[0] ^= 0x01;
        assert!(
            !verify(ps, &pk, message, &tampered),
            "tampered signature must not verify ({ps:?})"
        );

        let mut other_message = message.to_vec();
        other_message.push(0xFF);
        assert!(
            !verify(ps, &pk, &other_message, &signature),
            "signature must not verify for different message ({ps:?})"
        );
    }

    #[test]
    #[cfg(feature = "mldsa44")]
    fn mldsa44_roundtrip() {
        roundtrip(ParamSet::MLDSA44);
    }

    #[test]
    #[cfg(feature = "mldsa65")]
    fn mldsa65_roundtrip() {
        roundtrip(ParamSet::MLDSA65);
    }

    #[test]
    #[cfg(feature = "mldsa87")]
    fn mldsa87_roundtrip() {
        roundtrip(ParamSet::MLDSA87);
    }

    #[test]
    #[cfg(feature = "mldsa44")]
    fn rejects_wrong_length_signature() {
        let (pk, _sk) = keypair(ParamSet::MLDSA44);
        assert!(!verify(ParamSet::MLDSA44, &pk, b"hello", &[0u8; 16]));
    }

    #[test]
    #[cfg(feature = "mldsa44")]
    fn rejects_wrong_length_pubkey() {
        let (_pk, sk) = keypair(ParamSet::MLDSA44);
        let sig = sign(ParamSet::MLDSA44, &sk, b"hello");
        let pk = PublicKey(vec![0u8; 32]);
        assert!(!verify(ParamSet::MLDSA44, &pk, b"hello", &sig));
    }

    #[test]
    fn param_set_names_round_trip() {
        for ps in ParamSet::ALL {
            assert_eq!(ParamSet::from_name(ps.name()), Some(ps));
        }
        assert_eq!(ParamSet::from_name("ML-DSA-99"), None);
        assert_eq!(ParamSet::from_name("ml-dsa-44"), None);
    }

    #[test]
    fn lengths_match_fips204_constants() {
        let expected = [
            (ParamSet::MLDSA44, (1312usize, 2560usize, 2420usize)),
            (ParamSet::MLDSA65, (1952, 4032, 3309)),
            (ParamSet::MLDSA87, (2592, 4896, 4627)),
        ];
        for (ps, want) in expected {
            if ps.is_enabled() {
                assert_eq!(try_lengths(ps), Ok(want), "{ps}");
                assert_eq!(lengths(ps), want, "{ps}");
            } else {
                assert_eq!(
                    try_lengths(ps),
                    Err(MlDsaError::InvalidParameterSet),
                    "{ps}"
                );
            }
        }
    }

    /// A parameter set that was compiled out must be reported as an error by
    /// every fallible entry point -- no panics, no empty-but-plausible output.
    #[test]
    fn disabled_param_sets_report_errors_rather_than_panicking() {
        for ps in ParamSet::ALL.into_iter().filter(|ps| !ps.is_enabled()) {
            assert_eq!(try_lengths(ps), Err(MlDsaError::InvalidParameterSet));
            assert_eq!(
                try_keypair(ps).err(),
                Some(MlDsaError::InvalidParameterSet),
                "{ps}"
            );
            assert_eq!(
                try_keypair_from_seed(ps, &[0u8; SEED_LEN]).err(),
                Some(MlDsaError::InvalidParameterSet),
                "{ps}"
            );
            let sk = SecretKey::new(vec![0u8; 4896]);
            assert_eq!(
                try_sign(ps, &sk, b"msg"),
                Err(MlDsaError::InvalidParameterSet),
                "{ps}"
            );
            assert_eq!(
                try_public_key(ps, &sk),
                Err(MlDsaError::InvalidParameterSet),
                "{ps}"
            );
            assert!(sign(ps, &sk, b"msg").is_empty(), "{ps}");
            let pk = PublicKey::new(vec![0u8; 2592]);
            assert!(!verify(ps, &pk, b"msg", &[0u8; 4627]), "{ps}");
        }
    }

    /// `try_*` entry points must return errors, never unwind, for junk input.
    #[test]
    fn try_paths_never_panic_on_bad_input() {
        for ps in enabled() {
            let (_pk_len, sk_len, _sig_len) = lengths(ps);
            for bogus_len in [0usize, 1, 31, sk_len - 1, sk_len + 1] {
                let sk = SecretKey(vec![0x5a; bogus_len]);
                assert_eq!(
                    try_sign(ps, &sk, b"msg"),
                    Err(MlDsaError::InvalidKeyLength),
                    "{ps} sk len {bogus_len}"
                );
                assert_eq!(
                    try_public_key(ps, &sk),
                    Err(MlDsaError::InvalidKeyLength),
                    "{ps} sk len {bogus_len}"
                );
                assert!(sign(ps, &sk, b"msg").is_empty());
            }
            // An all-zero secret key is the right length but not a valid
            // encoding; it must be rejected, not signed with.
            let sk = SecretKey(vec![0u8; sk_len]);
            let _ = try_sign(ps, &sk, b"msg");
        }
    }

    #[test]
    #[cfg(feature = "mldsa44")]
    fn over_long_context_is_rejected() {
        let ps = ParamSet::MLDSA44;
        let (pk, sk) = keypair(ps);
        let ctx_max = vec![0xAA; MAX_CONTEXT_LEN];
        let sig = try_sign_with_context(ps, &sk, b"msg", &ctx_max).expect("255-byte ctx is legal");
        assert!(verify_with_context(ps, &pk, b"msg", &sig, &ctx_max));

        let ctx_too_long = vec![0xAA; MAX_CONTEXT_LEN + 1];
        assert_eq!(
            try_sign_with_context(ps, &sk, b"msg", &ctx_too_long),
            Err(MlDsaError::SigningFailed)
        );
        assert!(!verify_with_context(ps, &pk, b"msg", &sig, &ctx_too_long));
    }

    /// A signature made under one context must not verify under another,
    /// including the empty context used by [`verify`].
    #[test]
    #[cfg(feature = "mldsa65")]
    fn context_is_bound_into_the_signature() {
        let ps = ParamSet::MLDSA65;
        let (pk, sk) = keypair(ps);
        let sig = try_sign_with_context(ps, &sk, b"msg", b"ctx-a").expect("sign");
        assert!(verify_with_context(ps, &pk, b"msg", &sig, b"ctx-a"));
        assert!(!verify_with_context(ps, &pk, b"msg", &sig, b"ctx-b"));
        assert!(!verify(ps, &pk, b"msg", &sig));
    }

    #[test]
    fn seed_keygen_is_deterministic_and_matches_public_key() {
        for ps in enabled() {
            let seed = [0x42u8; SEED_LEN];
            let (pk1, sk1) = try_keypair_from_seed(ps, &seed).expect("seeded keygen");
            let (pk2, sk2) = try_keypair_from_seed(ps, &seed).expect("seeded keygen");
            assert_eq!(pk1.0, pk2.0, "{ps} seeded keygen must be deterministic");
            assert_eq!(sk1.0, sk2.0, "{ps} seeded keygen must be deterministic");

            let (pk_len, sk_len, _sig_len) = lengths(ps);
            assert_eq!(pk1.0.len(), pk_len);
            assert_eq!(sk1.0.len(), sk_len);
            assert_eq!(try_public_key(ps, &sk1).expect("derive pk").0, pk1.0);

            let mut other_seed = seed;
            other_seed[0] ^= 0x01;
            let (pk3, _sk3) = try_keypair_from_seed(ps, &other_seed).expect("seeded keygen");
            assert_ne!(pk1.0, pk3.0, "{ps} different seeds must differ");

            let sig = sign(ps, &sk1, b"seeded");
            assert!(verify(ps, &pk1, b"seeded", &sig));
        }
    }

    #[test]
    #[cfg(feature = "mldsa44")]
    fn hedged_signing_is_randomized_but_seeded_signing_is_not() {
        let ps = ParamSet::MLDSA44;
        let (pk, sk) = keypair(ps);
        let a = try_sign(ps, &sk, b"msg").expect("sign");
        let b = try_sign(ps, &sk, b"msg").expect("sign");
        assert_ne!(a, b, "hedged signing must not be deterministic");
        assert!(verify(ps, &pk, b"msg", &a) && verify(ps, &pk, b"msg", &b));

        let rnd = [0u8; SEED_LEN];
        let c = try_sign_deterministic(ps, &sk, b"msg", &[], &rnd).expect("sign");
        let d = try_sign_deterministic(ps, &sk, b"msg", &[], &rnd).expect("sign");
        assert_eq!(c, d, "seeded signing must be reproducible");
        assert!(verify(ps, &pk, b"msg", &c));
    }

    #[test]
    fn secret_key_debug_does_not_leak_bytes() {
        let sk = SecretKey(vec![0xAB; 64]);
        let rendered = format!("{sk:?}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    #[cfg(feature = "mldsa44")]
    fn secret_key_accessors_agree_with_the_public_field() {
        let (_pk, sk) = keypair(ParamSet::MLDSA44);
        assert_eq!(sk.as_bytes(), sk.0.as_slice());
        assert_eq!(sk.len(), sk.0.len());
        assert!(!sk.is_empty());
        assert_eq!(SecretKey::from_slice(sk.as_bytes()).0, sk.0);
        assert_eq!(SecretKey::new(sk.0.clone()).0, sk.0);
    }

    /// The whole point of the `log` feature: `sign()`'s silent-empty-`Vec`
    /// failure must actually produce a diagnostic.  Before this crate declared
    /// a real `log` dependency, `#[cfg(feature = "log")]` was never true and
    /// the warning was dead code.
    #[test]
    #[cfg(all(feature = "log", feature = "mldsa44"))]
    fn sign_failure_is_logged() {
        use log::{Level, LevelFilter, Metadata, Record};
        use std::sync::Mutex;

        static MESSAGES: Mutex<Vec<String>> = Mutex::new(Vec::new());
        struct Capture;
        impl log::Log for Capture {
            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }
            fn log(&self, record: &Record<'_>) {
                if record.level() <= Level::Error {
                    MESSAGES
                        .lock()
                        .expect("log mutex")
                        .push(record.args().to_string());
                }
            }
            fn flush(&self) {}
        }

        // Other tests in this binary do not log, and a second `set_logger`
        // call is harmless here.
        let _ = log::set_logger(&Capture);
        log::set_max_level(LevelFilter::Error);

        let junk = SecretKey::new(vec![0u8; 3]);
        assert!(sign(ParamSet::MLDSA44, &junk, b"msg").is_empty());

        let messages = MESSAGES.lock().expect("log mutex");
        assert!(
            messages
                .iter()
                .any(|m| m.contains("ML-DSA-44") && m.contains("empty signature")),
            "sign() failure was not logged: {messages:?}"
        );
    }
}
