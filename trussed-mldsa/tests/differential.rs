//! Differential test: `fips204` against RustCrypto's `ml-dsa`, and both
//! against this crate's public API.
//!
//! For random seeds, messages, contexts and `rnd` values, over all three
//! parameter sets, the two implementations must
//!
//! * derive byte-identical public and (expanded) secret keys from the same
//!   32-byte seed `ξ`;
//! * produce byte-identical signatures for the same key, message, context and
//!   `rnd` — both the deterministic variant (`rnd = 0^32`) and a pinned random
//!   `rnd`;
//! * accept each other's hedged signatures, and reject them once the message or
//!   the context is changed.
//!
//! The same checks run through `trussed_mldsa`'s own entry points, so whichever
//! backend the wrapper uses is held to the other implementation.
//!
//! The case generator is seeded.  Set `MLDSA_DIFF_SEED=<u64>` to replay a run
//! (the seed of a failing run is part of every assertion message) and
//! `MLDSA_DIFF_ITERATIONS=<n>` to change the number of cases per parameter set.

#![cfg(all(feature = "mldsa44", feature = "mldsa65", feature = "mldsa87"))]

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use trussed_mldsa::{ParamSet, PublicKey, SecretKey, MAX_CONTEXT_LEN, SEED_LEN};

/// Cases per parameter set when `MLDSA_DIFF_ITERATIONS` is not set.  Kept small
/// enough for an unoptimised `cargo test`; raise it for a longer soak.
const DEFAULT_ITERATIONS: usize = 24;

/// SplitMix64: a tiny, seedable generator for *test data*.  Not for keys.
struct CaseRng(u64);

impl CaseRng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn array(&mut self) -> [u8; SEED_LEN] {
        self.bytes(SEED_LEN).try_into().expect("32 bytes")
    }

    /// Mostly short messages, sometimes empty, sometimes a few kilobytes.
    fn message(&mut self) -> Vec<u8> {
        let len = match self.below(8) {
            0 => 0,
            1 => 4096 + self.below(4096),
            _ => self.below(512),
        };
        self.bytes(len)
    }

    /// Empty a quarter of the time, maximal (255 bytes) an eighth of the time.
    fn context(&mut self) -> Vec<u8> {
        let len = match self.below(8) {
            0 | 1 => 0,
            2 => MAX_CONTEXT_LEN,
            _ => 1 + self.below(MAX_CONTEXT_LEN),
        };
        self.bytes(len)
    }
}

fn env_or<T: std::str::FromStr>(name: &str, default: impl FnOnce() -> T) -> T {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{name}={value:?} is not a valid value")),
        Err(_) => default(),
    }
}

fn master_seed() -> u64 {
    env_or("MLDSA_DIFF_SEED", || {
        RandomState::new().build_hasher().finish()
    })
}

fn iterations() -> usize {
    env_or("MLDSA_DIFF_ITERATIONS", || DEFAULT_ITERATIONS)
}

macro_rules! differential {
    ($name:ident, $ps:expr, $fips:ident, $rc:ty, $case_offset:expr) => {
        #[test]
        fn $name() {
            use fips204::$fips as fips;
            use ml_dsa::{ExpandedSigningKey, KeyExport as _, Keypair as _, Signature, SigningKey};

            let ps: ParamSet = $ps;
            let master = master_seed();
            let iterations = iterations();
            // Distinct streams per parameter set, so replaying all three tests
            // with one MLDSA_DIFF_SEED still exercises different cases.
            let mut rng = CaseRng(master ^ $case_offset);
            println!("{ps}: MLDSA_DIFF_SEED={master} MLDSA_DIFF_ITERATIONS={iterations}");

            for i in 0..iterations {
                let at = format!("{ps} case {i} (MLDSA_DIFF_SEED={master})");
                let seed = rng.array();
                let message = rng.message();
                let ctx = rng.context();
                let rnd = rng.array();
                let zero_rnd = [0u8; SEED_LEN];

                // --- key generation from the seed -------------------------
                let (f_pk, f_sk) = fips::KG::keygen_from_seed(&seed);
                let f_pk_bytes = f_pk.clone().into_bytes();
                let f_sk_bytes = f_sk.clone().into_bytes();

                let rc_sk = SigningKey::<$rc>::from_seed(&seed.into());
                let rc_vk = rc_sk.verifying_key();
                assert_eq!(rc_sk.to_bytes().as_slice(), &seed[..], "{at}: seed export");
                #[allow(deprecated)] // the expanded encoding is what is compared
                let rc_sk_bytes = ExpandedSigningKey::<$rc>::from_seed(&seed.into()).to_expanded();
                assert_eq!(
                    rc_vk.encode().as_slice(),
                    &f_pk_bytes[..],
                    "{at}: public key"
                );
                assert_eq!(rc_sk_bytes.as_slice(), &f_sk_bytes[..], "{at}: secret key");

                let (w_pk, w_sk) =
                    trussed_mldsa::try_keypair_from_seed(ps, &seed).expect("wrapper keygen");
                assert_eq!(w_pk.as_bytes(), &f_pk_bytes[..], "{at}: wrapper public key");
                assert_eq!(w_sk.as_bytes(), &f_sk_bytes[..], "{at}: wrapper secret key");
                assert_eq!(
                    trussed_mldsa::try_public_key(ps, &w_sk)
                        .expect("wrapper pk")
                        .as_bytes(),
                    &f_pk_bytes[..],
                    "{at}: wrapper public key from secret key"
                );

                // --- deterministic signing (rnd = 0^32) ---------------------
                let f_det = f_sk
                    .try_sign_with_seed(&zero_rnd, &message, &ctx)
                    .expect("fips204 deterministic sign");
                let rc_esk = rc_sk.expanded_key();
                let rc_det = rc_esk
                    .sign_deterministic(&message, &ctx)
                    .expect("ml-dsa deterministic sign")
                    .encode();
                assert_eq!(
                    rc_det.as_slice(),
                    &f_det[..],
                    "{at}: deterministic signature"
                );
                let w_det =
                    trussed_mldsa::try_sign_deterministic(ps, &w_sk, &message, &ctx, &zero_rnd)
                        .expect("wrapper deterministic sign");
                assert_eq!(
                    w_det,
                    f_det.to_vec(),
                    "{at}: wrapper deterministic signature"
                );

                // --- pinned random rnd --------------------------------------
                let f_seeded = f_sk
                    .try_sign_with_seed(&rnd, &message, &ctx)
                    .expect("fips204 seeded sign");
                // ML-DSA.Sign (Algorithm 2) is Sign_internal over
                // M' = 0x00 || |ctx| || ctx || M.
                let ctx_len = [0u8, u8::try_from(ctx.len()).expect("ctx <= 255")];
                let rc_seeded = rc_esk
                    .sign_internal(&[&ctx_len, &ctx, &message], &rnd.into())
                    .encode();
                assert_eq!(
                    rc_seeded.as_slice(),
                    &f_seeded[..],
                    "{at}: seeded signature"
                );
                let w_seeded =
                    trussed_mldsa::try_sign_deterministic(ps, &w_sk, &message, &ctx, &rnd)
                        .expect("wrapper seeded sign");
                assert_eq!(
                    w_seeded,
                    f_seeded.to_vec(),
                    "{at}: wrapper seeded signature"
                );

                // --- hedged signatures verify across implementations --------
                let f_hedged = f_sk.try_sign(&message, &ctx).expect("fips204 hedged sign");
                let rc_hedged = rc_esk
                    .sign_randomized(&message, &ctx, &mut getrandom::SysRng)
                    .expect("ml-dsa hedged sign");
                let rc_hedged_bytes = rc_hedged.encode();
                let w_hedged = trussed_mldsa::try_sign_with_context(ps, &w_sk, &message, &ctx)
                    .expect("wrapper hedged sign");

                let f_as_rc =
                    Signature::<$rc>::try_from(&f_hedged[..]).expect("decode fips204 sig");
                assert!(
                    rc_vk.verify_with_context(&message, &ctx, &f_as_rc),
                    "{at}: ml-dsa rejected fips204"
                );
                let rc_as_f: [u8; fips::SIG_LEN] =
                    rc_hedged_bytes.as_slice().try_into().expect("sig len");
                assert!(
                    f_pk.verify(&message, &rc_as_f, &ctx),
                    "{at}: fips204 rejected ml-dsa"
                );
                let w_as_f: [u8; fips::SIG_LEN] = w_hedged.as_slice().try_into().expect("sig len");
                assert!(
                    f_pk.verify(&message, &w_as_f, &ctx),
                    "{at}: fips204 rejected wrapper"
                );
                assert!(
                    trussed_mldsa::verify_with_context(ps, &w_pk, &message, &f_hedged, &ctx),
                    "{at}: wrapper rejected fips204"
                );
                assert!(
                    trussed_mldsa::verify_with_context(ps, &w_pk, &message, &rc_hedged_bytes, &ctx),
                    "{at}: wrapper rejected ml-dsa"
                );

                // --- ... and both reject them for another message or context -
                let mut other_message = message.clone();
                match other_message.first_mut() {
                    Some(byte) => *byte ^= 0x01,
                    None => other_message.push(0x00),
                }
                let mut other_ctx = ctx.clone();
                match other_ctx.last_mut() {
                    Some(byte) => *byte ^= 0x80,
                    None => other_ctx.push(0x00),
                }
                assert!(
                    !rc_vk.verify_with_context(&other_message, &ctx, &f_as_rc),
                    "{at}: ml-dsa, other message"
                );
                assert!(
                    !rc_vk.verify_with_context(&message, &other_ctx, &f_as_rc),
                    "{at}: ml-dsa, other ctx"
                );
                assert!(
                    !f_pk.verify(&other_message, &rc_as_f, &ctx),
                    "{at}: fips204, other message"
                );
                assert!(
                    !f_pk.verify(&message, &rc_as_f, &other_ctx),
                    "{at}: fips204, other ctx"
                );
                assert!(
                    !trussed_mldsa::verify_with_context(ps, &w_pk, &other_message, &f_hedged, &ctx),
                    "{at}: wrapper, other message"
                );
                assert!(
                    !trussed_mldsa::verify_with_context(ps, &w_pk, &message, &f_hedged, &other_ctx),
                    "{at}: wrapper, other ctx"
                );

                // Keys decoded from bytes behave like the freshly generated ones.
                let f_pk_decoded =
                    fips::PublicKey::try_from_bytes(f_pk_bytes).expect("fips204 pk decode");
                assert!(
                    f_pk_decoded.verify(&message, &f_det, &ctx),
                    "{at}: decoded fips204 pk"
                );
                assert!(
                    trussed_mldsa::verify_with_context(
                        ps,
                        &PublicKey::new(f_pk_bytes.to_vec()),
                        &message,
                        &rc_det,
                        &ctx
                    ),
                    "{at}: wrapper verify of deterministic signature"
                );
                let reloaded = SecretKey::from_slice(&f_sk_bytes);
                assert_eq!(
                    trussed_mldsa::try_sign_deterministic(ps, &reloaded, &message, &ctx, &zero_rnd),
                    Ok(f_det.to_vec()),
                    "{at}: wrapper signature with a reloaded secret key"
                );
            }
        }
    };
}

differential!(
    mldsa44_matches_fips204,
    ParamSet::MLDSA44,
    ml_dsa_44,
    ml_dsa::MlDsa44,
    0x44
);
differential!(
    mldsa65_matches_fips204,
    ParamSet::MLDSA65,
    ml_dsa_65,
    ml_dsa::MlDsa65,
    0x65
);
differential!(
    mldsa87_matches_fips204,
    ParamSet::MLDSA87,
    ml_dsa_87,
    ml_dsa::MlDsa87,
    0x87
);
