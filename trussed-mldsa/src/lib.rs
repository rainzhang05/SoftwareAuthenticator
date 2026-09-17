//! Safe Rust wrapper around the pure-Rust ML-DSA implementation in RustCrypto's
//! `ml-dsa` crate.
//!
//! This crate exposes a small, stable surface (`keypair`, `sign`, `verify`)
//! for the three ML-DSA parameter sets defined in FIPS 204 (ML-DSA-44/65/87).
//! The implementation is provided by `ml-dsa`, which has no C dependencies,
//! forbids `unsafe` code, is written to run in constant time, and is covered by
//! the RustSec advisory process and by Wycheproof and NIST ACVP tests upstream.
//! This crate's own NIST ACVP known-answer tests live in
//! `tests/fips204_kat.rs`.
//!
//! Secret keys are zeroized on drop.
//!
//! # Seeds are the preferred secret key format
//!
//! A key pair is fully determined by its 32-byte FIPS 204 seed `ξ`, and seeds
//! are what should be stored (RFC 9964 §4).  [`try_keypair_from_seed`],
//! [`try_public_key_from_seed`] and [`try_sign_from_seed`] work from the seed
//! directly.
//!
//! The [`SecretKey`]-based entry points take the *expanded* FIPS 204 secret key
//! encoding (`skEncode`, 2,560–4,896 bytes) for compatibility and for NIST's
//! known-answer vectors, which only carry expanded keys.  `ml-dsa` deprecates
//! decoding that format because its decoder does not validate its input; this
//! crate therefore checks every coefficient range `skDecode` relies on before
//! decoding, so a malformed key is reported as
//! [`MlDsaError::InvalidKeyLength`] rather than reaching the decoder.
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
//! Note that `ml-dsa`'s own `signature::Signer` implementation is the
//! *deterministic* variant; this crate never uses it.  Hedged signing draws
//! `rnd` from the operating system's random number generator (`getrandom`).
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
// With no parameter set compiled in, every entry point reduces to its
// `InvalidParameterSet` arm and the backend helpers are unused.
#![cfg_attr(
    not(any(feature = "mldsa44", feature = "mldsa65", feature = "mldsa87")),
    allow(unused)
)]

use core::fmt;
use core::mem::size_of;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, Keypair,
    MlDsaParams, Signature, VerifyingKey, B32,
};
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

    /// The FIPS 204 parameters that fix the layout of the expanded secret key:
    /// `(η, k + ℓ)` from FIPS 204 Table 1.
    const fn secret_vector_layout(self) -> (u8, usize) {
        match self {
            ParamSet::MLDSA44 => (2, 4 + 4),
            ParamSet::MLDSA65 => (4, 6 + 5),
            ParamSet::MLDSA87 => (2, 8 + 7),
        }
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

/// Run `$body` with `$m` bound to the `ml-dsa` parameter type for `$ps`, or
/// evaluate `$disabled` when that parameter set was compiled out.
///
/// Dispatching through one macro keeps the three arms of every entry point
/// byte-for-byte identical, which is the whole point: a copy-paste slip
/// between `MlDsa44` and `MlDsa65` in a hand-written arm would be a silent,
/// security-relevant bug.
macro_rules! dispatch {
    ($ps:expr, |$m:ident| $body:block, $disabled:expr) => {
        match $ps {
            #[cfg(feature = "mldsa44")]
            ParamSet::MLDSA44 => {
                type $m = ml_dsa::MlDsa44;
                $body
            }
            #[cfg(feature = "mldsa65")]
            ParamSet::MLDSA65 => {
                type $m = ml_dsa::MlDsa65;
                $body
            }
            #[cfg(feature = "mldsa87")]
            ParamSet::MLDSA87 => {
                type $m = ml_dsa::MlDsa87;
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
    // `hybrid_array::Array<u8, N>` is `repr(transparent)` over `[u8; N]`, so its
    // size is the encoded length.
    dispatch!(
        ps,
        |P| {
            Ok((
                size_of::<EncodedVerifyingKey<P>>(),
                size_of::<ExpandedSigningKeyBytes<P>>(),
                size_of::<EncodedSignature<P>>(),
            ))
        },
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
/// not enabled, or [`MlDsaError::KeyGenFailed`] if the operating system's
/// random number generator fails.  Never panics.
pub fn try_keypair(ps: ParamSet) -> Result<(PublicKey, SecretKey), MlDsaError> {
    // Report a disabled parameter set before touching the RNG.
    try_lengths(ps)?;
    let mut seed = [0u8; SEED_LEN];
    let result = getrandom::fill(&mut seed)
        .map_err(|_| MlDsaError::KeyGenFailed)
        .and_then(|()| try_keypair_from_seed(ps, &seed));
    seed.zeroize();
    result
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
///
/// Callers that only need the public key, or only need to sign, should use
/// [`try_public_key_from_seed`] or [`try_sign_from_seed`], which never
/// materialise the expanded secret key encoding.
pub fn try_keypair_from_seed(
    ps: ParamSet,
    seed: &[u8; SEED_LEN],
) -> Result<(PublicKey, SecretKey), MlDsaError> {
    dispatch!(
        ps,
        |P| {
            let sk = expand_seed::<P>(seed);
            let pk = public_key_of(&sk);
            // `to_expanded` is deprecated upstream in favour of storing seeds;
            // producing the expanded encoding is this function's contract.
            #[allow(deprecated)]
            let mut encoded = sk.to_expanded();
            let secret = SecretKey(encoded.to_vec());
            encoded.zeroize();
            Ok((pk, secret))
        },
        Err(MlDsaError::InvalidParameterSet)
    )
}

/// Derive the public key of the key pair determined by the 32-byte FIPS 204
/// seed `ξ`, without materialising the expanded secret key encoding.  Never
/// panics.
pub fn try_public_key_from_seed(
    ps: ParamSet,
    seed: &[u8; SEED_LEN],
) -> Result<PublicKey, MlDsaError> {
    dispatch!(
        ps,
        |P| { Ok(public_key_of(&expand_seed::<P>(seed))) },
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
        |P| {
            let sk = decode_expanded::<P>(ps, sk)?;
            Ok(public_key_of(&sk))
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
    sign_expanded(ps, sk, message, ctx, None)
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
    sign_expanded(ps, sk, message, ctx, Some(rnd))
}

/// Sign `message` with the key pair determined by the 32-byte FIPS 204 seed
/// `ξ`, with an empty context string.  Returns the raw FIPS 204 signature.
///
/// Signing is hedged exactly as in [`try_sign`]; the difference is that the
/// key is expanded straight from the seed, the format credentials are stored
/// in, so no expanded secret key encoding is ever produced or decoded.  Never
/// panics.
pub fn try_sign_from_seed(
    ps: ParamSet,
    seed: &[u8; SEED_LEN],
    message: &[u8],
) -> Result<Vec<u8>, MlDsaError> {
    try_sign_from_seed_with_context(ps, seed, message, &[])
}

/// Like [`try_sign_from_seed`], but with an explicit FIPS 204 context string.
///
/// `ctx` longer than [`MAX_CONTEXT_LEN`] is rejected with
/// [`MlDsaError::SigningFailed`].  Never panics.
pub fn try_sign_from_seed_with_context(
    ps: ParamSet,
    seed: &[u8; SEED_LEN],
    message: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>, MlDsaError> {
    try_lengths(ps)?;
    if ctx.len() > MAX_CONTEXT_LEN {
        return Err(MlDsaError::SigningFailed);
    }
    dispatch!(
        ps,
        |P| { sign_with_key(&expand_seed::<P>(seed), message, ctx, None) },
        Err(MlDsaError::InvalidParameterSet)
    )
}

fn sign_expanded(
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
        |P| { sign_with_key(&decode_expanded::<P>(ps, sk)?, message, ctx, rnd) },
        Err(MlDsaError::InvalidParameterSet)
    )
}

/// FIPS 204 Algorithm 2, `ML-DSA.Sign`, over the external interface.
///
/// Without `rnd` this is the hedged variant, with 32 bytes of fresh randomness
/// from the operating system.  With `rnd` it is Algorithm 7,
/// `ML-DSA.Sign_internal`, over `M' = 0x00 || |ctx| || ctx || M` — which is
/// exactly what Algorithm 2 feeds it — so the caller's `rnd` is used verbatim.
/// `ml-dsa`'s `Signer` trait implementation is deliberately not used: it is the
/// deterministic variant.
fn sign_with_key<P: MlDsaParams>(
    sk: &ExpandedSigningKey<P>,
    message: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8; SEED_LEN]>,
) -> Result<Vec<u8>, MlDsaError> {
    let ctx_len = u8::try_from(ctx.len()).map_err(|_| MlDsaError::SigningFailed)?;
    let signature = match rnd {
        None => sk
            .sign_randomized(message, ctx, &mut getrandom::SysRng)
            .map_err(|_| MlDsaError::SigningFailed)?,
        Some(rnd) => {
            let mut rnd = B32::from(*rnd);
            let signature = sk.sign_internal(&[&[0x00, ctx_len], ctx, message], &rnd);
            rnd.zeroize();
            signature
        }
    };
    Ok(signature.encode().to_vec())
}

/// `ML-DSA.KeyGen_internal` (FIPS 204 Algorithm 6), keeping only the secret
/// half; [`public_key_of`] derives the public key from it.
fn expand_seed<P: MlDsaParams>(seed: &[u8; SEED_LEN]) -> ExpandedSigningKey<P> {
    let mut xi = B32::from(*seed);
    let sk = ExpandedSigningKey::<P>::from_seed(&xi);
    xi.zeroize();
    sk
}

fn public_key_of<P: MlDsaParams>(sk: &ExpandedSigningKey<P>) -> PublicKey {
    PublicKey(Keypair::verifying_key(sk).encode().to_vec())
}

/// `skDecode` (FIPS 204 Algorithm 25) for an untrusted expanded secret key.
///
/// `ml-dsa`'s decoder (`ExpandedSigningKey::from_expanded`) is deprecated
/// because it does not validate its input: it asserts, and so panics, if a
/// coefficient of `s1` or `s2` is out of range.  Every range it asserts on is
/// checked by [`expanded_key_is_well_formed`] first, so the decoder is only
/// ever handed input it accepts.  (`t0`'s 13-bit coefficients cover exactly
/// the range the decoder allows, so it needs no check.)  This mirrors what the
/// previous `fips204` backend accepted.
///
/// Seed-based callers never come through here.
fn decode_expanded<P: MlDsaParams>(
    ps: ParamSet,
    sk: &SecretKey,
) -> Result<ExpandedSigningKey<P>, MlDsaError> {
    let mut bytes = ExpandedSigningKeyBytes::<P>::try_from(sk.0.as_slice())
        .map_err(|_| MlDsaError::InvalidKeyLength)?;
    let result = if expanded_key_is_well_formed(ps, &bytes) {
        #[allow(deprecated)]
        Ok(ExpandedSigningKey::<P>::from_expanded(&bytes))
    } else {
        Err(MlDsaError::InvalidKeyLength)
    };
    bytes.zeroize();
    result
}

/// Whether every `s1` and `s2` coefficient of an expanded secret key encoding
/// is a valid `BitUnpack(·, η, η)` value, i.e. its raw field is at most `2η`.
///
/// The encoding is `ρ (32) || K (32) || tr (64) || s1 || s2 || t0`, with the
/// `k + ℓ` polynomials of `s1 || s2` packed at `bitlen(2η)` bits per
/// coefficient, least significant bit first.  All coefficients are checked
/// without an early exit.
fn expanded_key_is_well_formed(ps: ParamSet, sk: &[u8]) -> bool {
    const HEADER_LEN: usize = 32 + 32 + 64;
    const COEFFICIENTS: usize = 256;

    let (eta, polynomials) = ps.secret_vector_layout();
    let max = u32::from(2 * eta);
    let bits = (u32::BITS - max.leading_zeros()) as usize;
    let len = polynomials * COEFFICIENTS * bits / 8;
    let Some(packed) = sk.get(HEADER_LEN..HEADER_LEN + len) else {
        return false;
    };

    let mask = (1u32 << bits) - 1;
    let mut acc = 0u32;
    let mut acc_bits = 0usize;
    let mut out_of_range = 0u32;
    for &byte in packed {
        acc |= u32::from(byte) << acc_bits;
        acc_bits += 8;
        while acc_bits >= bits {
            out_of_range |= u32::from(acc & mask > max);
            acc >>= bits;
            acc_bits -= bits;
        }
    }
    out_of_range == 0
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
        |P| {
            let Ok(pk_bytes) = EncodedVerifyingKey::<P>::try_from(pk.0.as_slice()) else {
                return false;
            };
            // `sigDecode` rejects malformed hints and out-of-range `z`.
            let Ok(signature) = Signature::<P>::try_from(signature) else {
                return false;
            };
            VerifyingKey::<P>::decode(&pk_bytes).verify_with_context(message, ctx, &signature)
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

    /// The expanded-key layout used by the pre-decode validation must describe
    /// the backend's encoding exactly: `128 + (k + ℓ)·32·bitlen(2η) + k·32·13`.
    #[test]
    fn secret_vector_layout_matches_the_encoded_length() {
        for (ps, k) in [
            (ParamSet::MLDSA44, 4usize),
            (ParamSet::MLDSA65, 6),
            (ParamSet::MLDSA87, 8),
        ] {
            let Ok((_pk_len, sk_len, _sig_len)) = try_lengths(ps) else {
                continue;
            };
            let (eta, polynomials) = ps.secret_vector_layout();
            let bits = match eta {
                2 => 3,
                4 => 4,
                other => panic!("{ps}: unexpected eta {other}"),
            };
            assert_eq!(128 + polynomials * 32 * bits + k * 32 * 13, sk_len, "{ps}");
        }
    }

    /// An expanded secret key whose `s1`/`s2` coefficients are out of range
    /// would make the upstream decoder panic; it must be reported instead.
    #[test]
    fn malformed_expanded_secret_keys_are_rejected_without_panicking() {
        for ps in enabled() {
            let (pk, sk) = try_keypair_from_seed(ps, &[0x24; SEED_LEN]).expect("keygen");
            let (eta, polynomials) = ps.secret_vector_layout();
            let bits = if eta == 2 { 3 } else { 4 };
            let s_end = 128 + polynomials * 32 * bits;

            // First coefficient of s1, last coefficient of s2.
            for index in [128, s_end - 1] {
                let mut bytes = sk.as_bytes().to_vec();
                bytes[index] = 0xFF;
                let bad = SecretKey::new(bytes);
                assert_eq!(
                    try_sign(ps, &bad, b"msg"),
                    Err(MlDsaError::InvalidKeyLength),
                    "{ps} byte {index}"
                );
                assert_eq!(
                    try_sign_deterministic(ps, &bad, b"msg", &[], &[0; SEED_LEN]),
                    Err(MlDsaError::InvalidKeyLength),
                    "{ps} byte {index}"
                );
                assert_eq!(
                    try_public_key(ps, &bad),
                    Err(MlDsaError::InvalidKeyLength),
                    "{ps} byte {index}"
                );
                assert!(sign(ps, &bad, b"msg").is_empty(), "{ps} byte {index}");
            }

            // Every 13-bit t0 field is in range, so arbitrary t0 bytes decode.
            // The key no longer matches its public key, but it is well formed.
            let mut bytes = sk.as_bytes().to_vec();
            for byte in &mut bytes[s_end..] {
                *byte = 0xFF;
            }
            let odd = SecretKey::new(bytes);
            let sig = try_sign(ps, &odd, b"msg").expect("well-formed t0");
            assert_eq!(try_public_key(ps, &odd), Ok(pk.clone()), "{ps}");
            assert_eq!(sig.len(), lengths(ps).2, "{ps}");
        }
    }

    #[test]
    fn seed_entry_points_agree_with_the_expanded_key_ones() {
        for ps in enabled() {
            let seed = [0x5c; SEED_LEN];
            let (pk, sk) = try_keypair_from_seed(ps, &seed).expect("keygen");
            assert_eq!(try_public_key_from_seed(ps, &seed), Ok(pk.clone()), "{ps}");

            let sig = try_sign_from_seed(ps, &seed, b"from seed").expect("sign");
            assert!(verify(ps, &pk, b"from seed", &sig), "{ps}");
            let again = try_sign_from_seed(ps, &seed, b"from seed").expect("sign");
            assert_ne!(sig, again, "{ps}: seed signing must be hedged");

            let sig = try_sign_from_seed_with_context(ps, &seed, b"m", b"ctx").expect("sign");
            assert!(verify_with_context(ps, &pk, b"m", &sig, b"ctx"), "{ps}");
            assert!(!verify(ps, &pk, b"m", &sig), "{ps}");

            let sig = try_sign(ps, &sk, b"expanded").expect("sign");
            assert!(verify(ps, &pk, b"expanded", &sig), "{ps}");

            assert_eq!(
                try_sign_from_seed_with_context(ps, &seed, b"m", &[0; MAX_CONTEXT_LEN + 1]),
                Err(MlDsaError::SigningFailed),
                "{ps}"
            );
        }
        for ps in ParamSet::ALL.into_iter().filter(|ps| !ps.is_enabled()) {
            let seed = [0u8; SEED_LEN];
            assert_eq!(
                try_public_key_from_seed(ps, &seed),
                Err(MlDsaError::InvalidParameterSet)
            );
            assert_eq!(
                try_sign_from_seed(ps, &seed, b"msg"),
                Err(MlDsaError::InvalidParameterSet)
            );
        }
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
