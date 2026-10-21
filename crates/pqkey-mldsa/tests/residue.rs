//! Secrets left behind in the stack after signing and key derivation, and how
//! deep in the stack each operation reaches.
//!
//! FIPS 204 §3.6.3: "implementations of ML-DSA shall ensure that any
//! potentially sensitive intermediate data is destroyed as soon as it is no
//! longer needed."  ρ′ = SHAKE256(ξ ‖ k ‖ ℓ)[32..96] alone regenerates the
//! secret vectors s1 and s2, and K = [96..128] is the signing key's PRF key.
//! After each entry point returns, this test copies the dead stack below its
//! caller aside and looks in the copy for both 32-byte halves of ρ′, K, and a
//! control nobody computed, reporting how far below the caller it finds each.
//! Fixtures precede the probes; verification follows them. Linux also repeats
//! the operations in a child whose OS RNG is forced to fail.
//!
//! Those patterns are not every secret an operation leaves, so the test also
//! measures how far down the stack it goes.  `fill` first writes a canary
//! over the stack below the caller, and the deepest byte that no longer holds
//! it afterwards is the deepest the operation wrote.  Below the zeros its
//! scrub leaves, nothing but the scrub's own frame may have changed.  That
//! shows the operation stayed within the scrub, but not by how much: the
//! scrub zeroes all of its bound.  So [`unscrubbed`] also runs each operation
//! as `src/lib.rs` does, with no scrub after it, and the bound must reach at
//! least 25% deeper than the operation does there.
//!
//! It is its own program (`harness = false`), single-threaded on the main
//! thread, because it reads stack memory that other functions left behind:
//! `fill` and `capture` look at the same region below `main`'s frame through
//! buffers of their own.  `main` calls them and every operation itself, so
//! the region always lies at the same place.  Reading those bytes is outside
//! what Rust defines, so a clean result proves less than a dirty one; it found
//! the residue before the stack was scrubbed.

use core::mem::MaybeUninit;
use core::ops::Range;

use pqkey_mldsa::{
    MAX_CONTEXT_LEN, MlDsaError, ParamSet, PublicKey, SecretKey, try_keypair_from_seed,
    try_public_key, try_public_key_from_seed, try_sign, try_sign_deterministic, try_sign_from_seed,
    try_sign_from_seed_with_context, try_sign_with_context, verify_with_context,
};
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};

#[cfg(target_os = "linux")]
#[path = "support/rng_failure.rs"]
mod rng_failure;

#[cfg(target_os = "linux")]
use pqkey_mldsa::try_keypair;

enum Output {
    Signature(Vec<u8>),
    PublicKey(PublicKey),
    Keypair(PublicKey, SecretKey),
}

/// An entry point: its name, the context it signs with, the call, the same
/// work without the scrub (for the operations that get as far as the key),
/// and the error the call must return.
type Operation<'a> = (
    &'static str,
    &'a [u8],
    &'a dyn Fn() -> Result<Output, MlDsaError>,
    Option<&'a dyn Fn() -> Result<Output, MlDsaError>>,
    Option<MlDsaError>,
);

/// How far below `main` the probe reaches, more than signing ever uses.
const SCAN: usize = 2 * 1024 * 1024;

/// What `fill` writes: not zero, which is what scrubs and stack probes write.
const CANARY: u8 = 0xa5;

/// How far below the zeros a scrub leaves its own frame may reach: in a debug
/// build, the calls `zeroize` makes.
const SCRUB_FRAME: usize = 4 * 1024;

/// How many bytes `with_scrubbed_stack` in `src/lib.rs` zeroes after an
/// operation with `ps`.  The zeros every scrub leaves must reach at least
/// this far below `main`.
fn bound(ps: ParamSet) -> usize {
    match ps {
        ParamSet::MLDSA44 => 640 * 1024,
        ParamSet::MLDSA65 => 960 * 1024,
        ParamSet::MLDSA87 => 1600 * 1024,
    }
}

/// Overwrite the region below the caller with `CANARY`.
#[inline(never)]
fn fill() {
    let mut buffer: MaybeUninit<[u8; SCAN]> = MaybeUninit::uninit();
    let start = buffer.as_mut_ptr().cast::<u8>();
    for offset in 0..SCAN {
        // SAFETY: `start + offset` is inside `buffer`, which this frame owns.
        unsafe { core::ptr::write_volatile(start.add(offset), CANARY) };
    }
    core::hint::black_box(&buffer);
}

/// Copy the region below the caller into `copy`, allocated beforehand:
/// allocating it would itself run over that region.
#[inline(never)]
fn capture(copy: &mut [u8; SCAN]) {
    let buffer: MaybeUninit<[u8; SCAN]> = MaybeUninit::uninit();
    let start = buffer.as_ptr().cast::<u8>();
    for (offset, byte) in copy.iter_mut().enumerate() {
        // SAFETY: every byte read is inside `buffer`, which this frame owns.
        // The bytes are uninitialised as far as Rust is concerned: they hold
        // whatever earlier calls left there, which is what this test is after,
        // and they are only copied, never used as values of another type.
        *byte = unsafe { core::ptr::read_volatile(start.add(offset)) };
    }
    core::hint::black_box(&buffer);
}

/// How far below the caller, in bytes, each copy of `needle` in `copy` reaches.
fn find(copy: &[u8; SCAN], needle: &[u8]) -> Vec<usize> {
    copy.windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(offset, _)| SCAN - offset)
        .collect()
}

/// `depths` as the test reports them: how many, and how far down.
fn hits(depths: &[usize]) -> String {
    if depths.is_empty() {
        "0x".to_owned()
    } else {
        format!("{}x at {depths:?}", depths.len())
    }
}

/// How far below the caller, in bytes, `copy` holds something other than the
/// canary.  The bytes `capture` writes itself before it copies, the stack
/// probes of its frame, do not count; `baseline`, captured right after a
/// `fill`, holds something other than the canary there.
fn reach(copy: &[u8; SCAN], baseline: &[u8; SCAN]) -> usize {
    copy.iter()
        .zip(baseline.iter())
        .position(|(byte, seen)| *seen == CANARY && *byte != CANARY)
        .map_or(0, |offset| SCAN - offset)
}

/// The longest run of zeros in `copy`, which is what a scrub zeroed: from how
/// far below the caller it starts to how far it reaches.
fn zeros(copy: &[u8; SCAN]) -> Range<usize> {
    let (mut longest, mut start) = (0..0, 0);
    for (offset, byte) in copy.iter().enumerate() {
        if *byte != 0 {
            start = offset + 1;
        } else if offset + 1 - start > longest.len() {
            longest = start..offset + 1;
        }
    }
    SCAN - longest.end..SCAN - longest.start
}

/// ρ′ and K of the key generated from `seed` with parameters (k, ℓ).
fn rho_prime_and_key(seed: &[u8; 32], k: u8, l: u8) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut out = [0u8; 128];
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[k, l]);
    shake.finalize_xof().read(&mut out);
    (
        out[32..64].try_into().expect("32 bytes"),
        out[96..128].try_into().expect("32 bytes"),
        out[64..96].try_into().expect("32 bytes"),
    )
}

/// What `src/lib.rs` runs on the stack it then scrubs, rebuilt from `ml-dsa`
/// and run with no scrub after it: how deep each operation reaches by itself.
///
/// `run_below`, `expand_seed`, `public_key_of`, `sign_with_key` and
/// `decode_expanded` are those of `src/lib.rs`, called as its entry points
/// call them, from `run_below`, but with nothing scrubbing after it.
/// `decode_expanded` leaves out the range check, a call that returns before
/// decoding starts; for the same reason, the malformed keys, which stop at
/// that check, have no run here.  Debug builds reach deepest, and in one
/// every function's frame follows its source: these copies' frames match the
/// library's to within 48 bytes, so their depths are the wrapper's own plus
/// the frames of the entry points above them.  An optimised build can inline
/// the copies differently from the library.  Keep this in step with
/// `src/lib.rs`.
mod unscrubbed {
    use ml_dsa::{
        B32, ExpandedSigningKey, ExpandedSigningKeyBytes, Keypair, MlDsa44, MlDsa65, MlDsa87,
        MlDsaParams,
    };
    use pqkey_mldsa::{MlDsaError, ParamSet, PublicKey, SEED_LEN, SecretKey};
    use zeroize::Zeroize;

    /// Run `$body` with `$m` bound to the `ml-dsa` parameter type for `$ps`.
    macro_rules! dispatch {
        ($ps:expr, |$m:ident| $body:block) => {
            match $ps {
                ParamSet::MLDSA44 => {
                    type $m = MlDsa44;
                    $body
                }
                ParamSet::MLDSA65 => {
                    type $m = MlDsa65;
                    $body
                }
                ParamSet::MLDSA87 => {
                    type $m = MlDsa87;
                    $body
                }
            }
        };
    }

    /// `try_keypair_from_seed`.
    pub fn keypair_from_seed(
        ps: ParamSet,
        seed: &[u8; SEED_LEN],
    ) -> Result<(PublicKey, SecretKey), MlDsaError> {
        dispatch!(ps, |P| {
            run_below(|| {
                let sk = expand_seed::<P>(seed);
                let pk = public_key_of(&sk);
                #[allow(deprecated)]
                let mut encoded = sk.to_expanded();
                let secret = SecretKey::new(encoded.to_vec());
                encoded.zeroize();
                Ok((pk, secret))
            })
        })
    }

    /// `try_public_key_from_seed`.
    pub fn public_key_from_seed(
        ps: ParamSet,
        seed: &[u8; SEED_LEN],
    ) -> Result<PublicKey, MlDsaError> {
        dispatch!(ps, |P| {
            run_below(|| Ok(public_key_of(&expand_seed::<P>(seed))))
        })
    }

    /// `try_public_key`.
    pub fn public_key(ps: ParamSet, sk: &SecretKey) -> Result<PublicKey, MlDsaError> {
        dispatch!(ps, |P| {
            run_below(|| {
                let sk = decode_expanded::<P>(sk)?;
                Ok(public_key_of(&sk))
            })
        })
    }

    /// `try_sign_from_seed_with_context`.
    pub fn sign_from_seed(
        ps: ParamSet,
        seed: &[u8; SEED_LEN],
        message: &[u8],
        ctx: &[u8],
    ) -> Result<Vec<u8>, MlDsaError> {
        dispatch!(ps, |P| {
            run_below(|| sign_with_key(&expand_seed::<P>(seed), message, ctx, None))
        })
    }

    /// `try_sign_with_context` without `rnd`, `try_sign_deterministic` with it.
    pub fn sign(
        ps: ParamSet,
        sk: &SecretKey,
        message: &[u8],
        ctx: &[u8],
        rnd: Option<&[u8; SEED_LEN]>,
    ) -> Result<Vec<u8>, MlDsaError> {
        dispatch!(ps, |P| {
            run_below(|| sign_with_key(&decode_expanded::<P>(sk)?, message, ctx, rnd))
        })
    }

    #[inline(never)]
    fn run_below<T>(operation: impl FnOnce() -> T) -> T {
        operation()
    }

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

    fn expand_seed<P: MlDsaParams>(seed: &[u8; SEED_LEN]) -> ExpandedSigningKey<P> {
        let mut xi = B32::from(*seed);
        let sk = ExpandedSigningKey::<P>::from_seed(&xi);
        xi.zeroize();
        sk
    }

    fn public_key_of<P: MlDsaParams>(sk: &ExpandedSigningKey<P>) -> PublicKey {
        PublicKey::new(Keypair::verifying_key(sk).encode().to_vec())
    }

    fn decode_expanded<P: MlDsaParams>(
        sk: &SecretKey,
    ) -> Result<ExpandedSigningKey<P>, MlDsaError> {
        let mut bytes = ExpandedSigningKeyBytes::<P>::try_from(sk.as_bytes())
            .map_err(|_| MlDsaError::InvalidKeyLength)?;
        #[allow(deprecated)]
        let result = Ok(ExpandedSigningKey::<P>::from_expanded(&bytes));
        bytes.zeroize();
        result
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    let rng_failed = rng_failure::is_child();
    #[cfg(not(target_os = "linux"))]
    let rng_failed = false;

    let seed = [0x5A; 32];
    let mut control = [0u8; 32];
    let mut shake = Shake256::default();
    shake.update(b"never computed by the signer");
    shake.finalize_xof().read(&mut control);
    let mut copy: Box<[u8; SCAN]> = vec![0; SCAN]
        .into_boxed_slice()
        .try_into()
        .expect("SCAN bytes");
    let mut baseline: Box<[u8; SCAN]> = vec![0; SCAN]
        .into_boxed_slice()
        .try_into()
        .expect("SCAN bytes");

    // What the copies cannot see: the bytes `capture` changes before it reads,
    // such as the zero word a compiler's stack probes leave on each page of
    // its frame.
    fill();
    capture(&mut baseline);
    let blind = baseline.iter().filter(|byte| **byte != CANARY).count();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let (arch, os) = (std::env::consts::ARCH, std::env::consts::OS);
    println!(
        "{profile} build for {arch}-{os} (RNG failure: {rng_failed}): \
         {blind} of the {SCAN} bytes below main hidden from the copies"
    );
    assert!(blind < SCAN / 64, "the copies miss {blind} bytes");

    let mut failures = Vec::new();
    let mut shortfalls = Vec::new();
    for (ps, k, l) in [
        (ParamSet::MLDSA44, 4, 4),
        (ParamSet::MLDSA65, 6, 5),
        (ParamSet::MLDSA87, 8, 7),
    ] {
        if !ps.is_enabled() {
            continue;
        }
        let (rho_prime, key, rho_prime_tail) = rho_prime_and_key(&seed, k, l);
        let (pk, sk) = try_keypair_from_seed(ps, &seed).expect("fixture");
        let mut malformed = sk.as_bytes().to_vec();
        malformed[128] = 0xff; // out-of-range first s1 coefficient
        let malformed = SecretKey::new(malformed);
        let maximum = [0xaa; MAX_CONTEXT_LEN];
        let overlong = [0xaa; MAX_CONTEXT_LEN + 1];
        let rnd = [0; 32];
        let message = b"message";
        let signing_error = rng_failed.then_some(MlDsaError::SigningFailed);
        let operations: [Operation<'_>; 15] = [
            (
                "try_sign_from_seed",
                &[],
                &|| try_sign_from_seed(ps, &seed, message).map(Output::Signature),
                Some(&|| {
                    unscrubbed::sign_from_seed(ps, &seed, message, &[]).map(Output::Signature)
                }),
                signing_error,
            ),
            (
                "try_public_key_from_seed",
                &[],
                &|| try_public_key_from_seed(ps, &seed).map(Output::PublicKey),
                Some(&|| unscrubbed::public_key_from_seed(ps, &seed).map(Output::PublicKey)),
                None,
            ),
            (
                "seed context",
                b"ctx",
                &|| {
                    try_sign_from_seed_with_context(ps, &seed, message, b"ctx")
                        .map(Output::Signature)
                },
                Some(&|| {
                    unscrubbed::sign_from_seed(ps, &seed, message, b"ctx").map(Output::Signature)
                }),
                signing_error,
            ),
            (
                "seed maximum context",
                &maximum,
                &|| {
                    try_sign_from_seed_with_context(ps, &seed, message, &maximum)
                        .map(Output::Signature)
                },
                Some(&|| {
                    unscrubbed::sign_from_seed(ps, &seed, message, &maximum).map(Output::Signature)
                }),
                signing_error,
            ),
            (
                "try_keypair_from_seed",
                &[],
                &|| try_keypair_from_seed(ps, &seed).map(|(pk, sk)| Output::Keypair(pk, sk)),
                Some(&|| {
                    unscrubbed::keypair_from_seed(ps, &seed).map(|(pk, sk)| Output::Keypair(pk, sk))
                }),
                None,
            ),
            (
                "try_public_key",
                &[],
                &|| try_public_key(ps, &sk).map(Output::PublicKey),
                Some(&|| unscrubbed::public_key(ps, &sk).map(Output::PublicKey)),
                None,
            ),
            (
                "try_sign",
                &[],
                &|| try_sign(ps, &sk, message).map(Output::Signature),
                Some(&|| unscrubbed::sign(ps, &sk, message, &[], None).map(Output::Signature)),
                signing_error,
            ),
            (
                "expanded context",
                b"ctx",
                &|| try_sign_with_context(ps, &sk, message, b"ctx").map(Output::Signature),
                Some(&|| unscrubbed::sign(ps, &sk, message, b"ctx", None).map(Output::Signature)),
                signing_error,
            ),
            (
                "deterministic signing",
                &[],
                &|| try_sign_deterministic(ps, &sk, message, &[], &rnd).map(Output::Signature),
                Some(&|| {
                    unscrubbed::sign(ps, &sk, message, &[], Some(&rnd)).map(Output::Signature)
                }),
                None,
            ),
            (
                "deterministic maximum context",
                &maximum,
                &|| try_sign_deterministic(ps, &sk, message, &maximum, &rnd).map(Output::Signature),
                Some(&|| {
                    unscrubbed::sign(ps, &sk, message, &maximum, Some(&rnd)).map(Output::Signature)
                }),
                None,
            ),
            (
                "seed overlong context",
                &overlong,
                &|| {
                    try_sign_from_seed_with_context(ps, &seed, message, &overlong)
                        .map(Output::Signature)
                },
                None,
                Some(MlDsaError::SigningFailed),
            ),
            (
                "expanded overlong context",
                &overlong,
                &|| try_sign_with_context(ps, &sk, message, &overlong).map(Output::Signature),
                None,
                Some(MlDsaError::SigningFailed),
            ),
            (
                "malformed expanded signing",
                &[],
                &|| try_sign(ps, &malformed, message).map(Output::Signature),
                None,
                Some(MlDsaError::InvalidKeyLength),
            ),
            (
                "malformed public key",
                &[],
                &|| try_public_key(ps, &malformed).map(Output::PublicKey),
                None,
                Some(MlDsaError::InvalidKeyLength),
            ),
            (
                "malformed deterministic signing",
                &[],
                &|| {
                    try_sign_deterministic(ps, &malformed, message, &[], &rnd)
                        .map(Output::Signature)
                },
                None,
                Some(MlDsaError::InvalidKeyLength),
            ),
        ];
        #[cfg(target_os = "linux")]
        if rng_failed
            && ps
                == ParamSet::ALL
                    .into_iter()
                    .find(|ps| ps.is_enabled())
                    .expect("enabled set")
        {
            rng_failure::block_getrandom();
            assert_eq!(try_keypair(ps).err(), Some(MlDsaError::KeyGenFailed));
        }
        for (name, context, operation, without_scrub, expected_error) in operations {
            fill();
            let result = core::hint::black_box(operation());
            capture(&mut copy);
            let reached = reach(&copy, &baseline);
            let zeroed = zeros(&copy);
            let found =
                [&rho_prime, &rho_prime_tail, &key, &control].map(|needle| find(&copy, needle));
            let summary = format!(
                "rho' {}/{}, K {}, control {}",
                hits(&found[0]),
                hits(&found[1]),
                hits(&found[2]),
                hits(&found[3])
            );
            if found.iter().any(|depths| !depths.is_empty()) {
                failures.push(format!("{ps} {name}: {summary}"));
            }
            let mut stack = format!("reached {reached} bytes down");
            if reached + 4096 > SCAN {
                shortfalls.push(format!("{ps} {name}: reached the end of the {SCAN} bytes"));
            }
            // An overlong context is rejected before the key is expanded or
            // decoded, so there is nothing to scrub.
            if context.len() <= MAX_CONTEXT_LEN {
                stack += &format!(", zeros from {} to {} bytes down", zeroed.start, zeroed.end);
                // The calls made once the scrub has returned overwrite the top
                // of its zeros, but not how deep they reach.
                if zeroed.end < bound(ps) {
                    shortfalls.push(format!(
                        "{ps} {name}: the scrub's zeros reach {} bytes down, not {}",
                        zeroed.end,
                        bound(ps)
                    ));
                }
                if reached > zeroed.end + SCRUB_FRAME {
                    shortfalls.push(format!(
                        "{ps} {name}: reached {reached} bytes down, {} below the scrub's zeros",
                        reached - zeroed.end
                    ));
                }
            } else {
                stack += ", returned before any scrub";
            }
            let mut unscrubbed_result = None;
            if let Some(without_scrub) = without_scrub {
                fill();
                let result = core::hint::black_box(without_scrub());
                capture(&mut copy);
                let alone = reach(&copy, &baseline);
                let left = [&rho_prime, &rho_prime_tail, &key].map(|needle| find(&copy, needle));
                stack += &format!(
                    "; without it {alone} bytes ({}% of the bound), leaving rho' {}x/{}x, K {}x",
                    alone * 100 / bound(ps),
                    left[0].len(),
                    left[1].len(),
                    left[2].len()
                );
                if alone + 4096 > SCAN {
                    shortfalls.push(format!(
                        "{ps} {name}: reached the end of the {SCAN} bytes without its scrub"
                    ));
                }
                if alone * 5 > bound(ps) * 4 {
                    shortfalls.push(format!(
                        "{ps} {name}: reaches {alone} bytes down without its scrub, \
                         more than 80% of the {}-byte bound",
                        bound(ps)
                    ));
                }
                unscrubbed_result = Some(result);
            }
            println!("{ps} {name} (RNG failure: {rng_failed}): {summary}\n  stack: {stack}");
            let check = |result, how: &str| match (result, expected_error) {
                (Err(actual), Some(expected)) => assert_eq!(actual, expected, "{ps} {name}{how}"),
                (Ok(Output::Signature(signature)), None) => assert!(
                    verify_with_context(ps, &pk, message, &signature, context),
                    "{ps} {name}{how}"
                ),
                (Ok(Output::PublicKey(actual)), None) => {
                    assert_eq!(actual, pk, "{ps} {name}{how}");
                }
                (Ok(Output::Keypair(actual_pk, actual_sk)), None) => {
                    assert_eq!(actual_pk, pk, "{ps} {name}{how}");
                    assert_eq!(actual_sk.as_bytes(), sk.as_bytes(), "{ps} {name}{how}");
                }
                _ => panic!("unexpected result: {ps} {name}{how}"),
            };
            check(result, "");
            if let Some(result) = unscrubbed_result {
                check(result, " without the scrub");
            }
        }
    }
    assert!(
        failures.is_empty() && shortfalls.is_empty(),
        "secrets left in the stack after {failures:?}; scrubs falling short: {shortfalls:?}"
    );
    println!("no ML-DSA secrets left in the stack, and each scrub has 25% to spare");
    #[cfg(target_os = "linux")]
    if !rng_failed {
        rng_failure::run_child();
    }
}
