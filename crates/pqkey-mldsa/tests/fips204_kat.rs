//! FIPS 204 (ML-DSA) known-answer tests against the official NIST ACVP vectors,
//! plus cross-parameter-set confusion tests.
//!
//! The round-trip tests in `src/lib.rs` (generate, sign, verify with our own
//! code) would pass for *any* self-consistent signature scheme.  These tests
//! are the ones that pin the implementation to FIPS 204: every expected value
//! below was produced by NIST's reference implementation, not by this crate.
//!
//! # Where the vectors come from
//!
//! `tests/vectors/*.kat` are hand-picked subsets of
//! <https://github.com/usnistgov/ACVP-Server> `gen-val/json-files/`
//! `ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json`, commit
//! `975de31eb83d87039ec88934fdc47d8c312b892d`.  They are vendored so the test
//! suite is hermetic; each file's header records the exact provenance and the
//! upstream `tcId`s are preserved so a case can be traced back.
//!
//! Only the `signatureInterface: external`, `preHash: pure` groups are used,
//! because plain `ML-DSA.Sign`/`ML-DSA.Verify` is what this crate implements.

// Every parameter set is exercised, so the whole suite needs all three
// compiled in.  A reduced-feature build simply has no KATs to run.
#![cfg(all(feature = "mldsa44", feature = "mldsa65", feature = "mldsa87"))]

use pqkey_mldsa::{
    lengths, try_keypair_from_seed, try_public_key, try_sign, try_sign_deterministic,
    try_sign_with_context, verify, verify_with_context, MlDsaError, ParamSet, PublicKey, SecretKey,
    SEED_LEN,
};

const KEYGEN_KAT: &str = include_str!("vectors/mldsa_keygen.kat");
const SIGGEN_KAT: &str = include_str!("vectors/mldsa_siggen.kat");
const SIGVER_KAT: &str = include_str!("vectors/mldsa_sigver.kat");

// ---------------------------------------------------------------------------
// Minimal parser for the vendored `key = value` vector format.
//
// Deliberately dependency-free: pulling `serde_json` + `hex` into a crypto
// wrapper's dependency graph just to read test data is a poor trade.
// ---------------------------------------------------------------------------

struct Case {
    kind: String,
    fields: Vec<(String, String)>,
}

impl Case {
    fn get(&self, key: &str) -> &str {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("vector case {} is missing field `{key}`", self.label()))
    }

    fn bytes(&self, key: &str) -> Vec<u8> {
        unhex(self.get(key), &self.label())
    }

    fn seed(&self, key: &str) -> [u8; SEED_LEN] {
        let bytes = self.bytes(key);
        <[u8; SEED_LEN]>::try_from(bytes.as_slice())
            .unwrap_or_else(|_| panic!("{} field `{key}` must be {SEED_LEN} bytes", self.label()))
    }

    fn flag(&self, key: &str) -> bool {
        match self.get(key) {
            "true" => true,
            "false" => false,
            other => panic!(
                "{} field `{key}` must be true/false, got {other:?}",
                self.label()
            ),
        }
    }

    fn param_set(&self) -> ParamSet {
        let name = self.get("parameterSet");
        ParamSet::from_name(name).unwrap_or_else(|| panic!("unknown parameter set {name:?}"))
    }

    fn label(&self) -> String {
        let ps = self
            .fields
            .iter()
            .find(|(k, _)| k == "parameterSet")
            .map(|(_, v)| v.as_str())
            .unwrap_or("?");
        let tc = self
            .fields
            .iter()
            .find(|(k, _)| k == "tcId")
            .map(|(_, v)| v.as_str())
            .unwrap_or("?");
        format!("{} {ps} tcId {tc}", self.kind)
    }
}

// `as_chunks` (clippy's suggestion) is only stable since Rust 1.88, and the
// workspace declares `rust-version = "1.85"`.
#[allow(clippy::chunks_exact_to_as_chunks)]
fn unhex(s: &str, label: &str) -> Vec<u8> {
    let digit = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("{label}: invalid hex digit {:?}", c as char),
        }
    };
    let mut pairs = s.as_bytes().chunks_exact(2);
    let out: Vec<u8> = pairs
        .by_ref()
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect();
    assert!(
        pairs.remainder().is_empty(),
        "{label}: hex string has an odd number of digits"
    );
    out
}

fn parse(raw: &str) -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(kind) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            cases.push(Case {
                kind: kind.to_string(),
                fields: Vec::new(),
            });
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("malformed vector line: {line:?}"));
        cases
            .last_mut()
            .expect("vector file must start with a `[kind]` header")
            .fields
            .push((key.trim().to_string(), value.trim().to_string()));
    }
    assert!(!cases.is_empty(), "vector file contained no cases");
    cases
}

/// Guard against a truncated or mis-parsed vector file silently turning a KAT
/// into a no-op: every parameter set must actually be exercised.
fn assert_coverage(cases: &[Case], minimum_per_param_set: usize, what: &str) {
    for ps in ParamSet::ALL {
        let n = cases.iter().filter(|c| c.param_set() == ps).count();
        assert!(
            n >= minimum_per_param_set,
            "{what}: only {n} {ps} cases, expected at least {minimum_per_param_set}"
        );
    }
}

// ---------------------------------------------------------------------------
// Known-answer tests
// ---------------------------------------------------------------------------

/// Proves `ML-DSA.KeyGen_internal` (FIPS 204 Algorithm 6) conformance: the
/// expansion of the 32-byte seed ξ into (ρ, K, tr, s1, s2, t0) and the
/// encoding of both keys must match NIST byte for byte.  A non-conformant
/// implementation with self-consistent keys fails here.
#[test]
fn keygen_known_answer() {
    let cases = parse(KEYGEN_KAT);
    assert_coverage(&cases, 3, "keyGen");

    for case in &cases {
        assert_eq!(case.kind, "keygen");
        let label = case.label();
        let ps = case.param_set();
        let seed = case.seed("seed");
        let expected_pk = case.bytes("pk");
        let expected_sk = case.bytes("sk");

        let (pk, sk) = try_keypair_from_seed(ps, &seed).expect("seeded keygen");
        assert_eq!(pk.as_bytes(), expected_pk, "{label}: public key mismatch");
        assert_eq!(sk.as_bytes(), expected_sk, "{label}: secret key mismatch");

        // The decoded secret key must carry the same public key.
        assert_eq!(
            try_public_key(ps, &sk).expect("derive pk").as_bytes(),
            expected_pk,
            "{label}: public key derived from the secret key mismatch"
        );
    }
}

/// Proves `ML-DSA.Sign` (FIPS 204 Algorithm 2) conformance over the external
/// interface: message domain separation (`M' = 0x00 || |ctx| || ctx || M`),
/// the rejection-sampling loop, and signature encoding must reproduce NIST's
/// bytes exactly for a pinned `rnd`.
#[test]
fn siggen_known_answer() {
    let cases = parse(SIGGEN_KAT);
    assert_coverage(&cases, 3, "sigGen");

    let mut deterministic_cases = 0usize;
    let mut hedged_cases = 0usize;
    let mut empty_context_cases = 0usize;

    for case in &cases {
        assert_eq!(case.kind, "siggen");
        let label = case.label();
        let ps = case.param_set();
        let sk = SecretKey::new(case.bytes("sk"));
        let pk = PublicKey::new(case.bytes("pk"));
        let ctx = case.bytes("context");
        let message = case.bytes("message");
        let expected_sig = case.bytes("signature");
        let rnd = case.seed("rnd");

        if case.flag("deterministic") {
            // FIPS 204's deterministic variant is exactly rnd = 0^32.
            assert_eq!(
                rnd, [0u8; SEED_LEN],
                "{label}: deterministic rnd must be 0^32"
            );
            deterministic_cases += 1;
        } else {
            hedged_cases += 1;
        }

        let sig = try_sign_deterministic(ps, &sk, &message, &ctx, &rnd)
            .unwrap_or_else(|e| panic!("{label}: signing failed: {e}"));
        assert_eq!(sig, expected_sig, "{label}: signature mismatch");

        // The vector's own public key must accept it, through our verifier.
        assert!(
            verify_with_context(ps, &pk, &message, &sig, &ctx),
            "{label}: NIST signature rejected by verify_with_context"
        );
        assert_eq!(
            try_public_key(ps, &sk).expect("derive pk").as_bytes(),
            pk.as_bytes(),
            "{label}: secret key does not carry the vector's public key"
        );

        if ctx.is_empty() {
            empty_context_cases += 1;
            // The production entry points pin ctx to the empty string, so for
            // these cases they must behave identically.
            assert!(
                verify(ps, &pk, &message, &sig),
                "{label}: NIST signature rejected by verify()"
            );
            // try_sign() is defined as try_sign_with_context(.., &[]); pin that
            // the empty-context spelling really is the one under test.
            let hedged = try_sign_with_context(ps, &sk, &message, &[]).expect("sign");
            assert!(
                verify(ps, &pk, &message, &hedged),
                "{label}: empty-context signing disagrees with verify()"
            );
        }
    }

    assert!(
        deterministic_cases >= 9,
        "expected the deterministic groups"
    );
    assert!(
        hedged_cases >= 3,
        "expected the hedged (rnd-carrying) groups"
    );
    assert!(
        empty_context_cases >= 3,
        "expected empty-context cases so verify() itself is covered"
    );
}

/// Proves `ML-DSA.Verify` (FIPS 204 Algorithm 3) conformance in both
/// directions: NIST's good signatures must be accepted and NIST's
/// deliberately corrupted ones (modified message, z, commitment, or hint)
/// must be rejected.  An implementation that accepts everything, or that
/// rejects everything, fails here.
#[test]
fn sigver_known_answer() {
    let cases = parse(SIGVER_KAT);
    assert_coverage(&cases, 6, "sigVer");

    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for case in &cases {
        assert_eq!(case.kind, "sigver");
        let label = case.label();
        let ps = case.param_set();
        let pk = PublicKey::new(case.bytes("pk"));
        let ctx = case.bytes("context");
        let message = case.bytes("message");
        let signature = case.bytes("signature");
        let expected = case.flag("testPassed");
        let reason = case.get("reason");

        assert_eq!(
            verify_with_context(ps, &pk, &message, &signature, &ctx),
            expected,
            "{label}: expected testPassed={expected} ({reason})"
        );

        if ctx.is_empty() {
            assert_eq!(
                verify(ps, &pk, &message, &signature),
                expected,
                "{label}: verify() disagrees with the vector ({reason})"
            );
        }

        if expected {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    assert!(accepted >= 3, "expected must-verify cases");
    assert!(rejected >= 3, "expected must-reject cases");
}

/// The production (hedged) signing path must interoperate with NIST-generated
/// keys: sign with `try_sign`, verify with the vector's own public key.
#[test]
fn production_path_interoperates_with_nist_keys() {
    for case in parse(SIGGEN_KAT) {
        let label = case.label();
        let ps = case.param_set();
        let sk = SecretKey::new(case.bytes("sk"));
        let pk = PublicKey::new(case.bytes("pk"));

        let message = b"authenticatorData || clientDataHash";
        let sig = try_sign(ps, &sk, message).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(sig.len(), lengths(ps).2, "{label}: signature length");
        assert!(verify(ps, &pk, message, &sig), "{label}: hedged signature");
    }
}

// ---------------------------------------------------------------------------
// Cross-parameter-set confusion
// ---------------------------------------------------------------------------

fn other_param_sets(ps: ParamSet) -> impl Iterator<Item = ParamSet> {
    ParamSet::ALL.into_iter().filter(move |o| *o != ps)
}

/// A signature produced under one parameter set must never verify under
/// another, even with that set's genuine public key.
#[test]
fn signature_does_not_verify_under_another_param_set() {
    let message = b"cross-parameter-set confusion";
    let keys: Vec<(ParamSet, PublicKey, Vec<u8>)> = ParamSet::ALL
        .into_iter()
        .map(|ps| {
            let (pk, sk) = pqkey_mldsa::keypair(ps);
            let sig = try_sign(ps, &sk, message).expect("sign");
            (ps, pk, sig)
        })
        .collect();

    for (ps, _pk, sig) in &keys {
        for (other, other_pk, _other_sig) in &keys {
            if other == ps {
                continue;
            }
            assert!(
                !verify(*other, other_pk, message, sig),
                "{ps} signature verified under {other}"
            );
        }
    }
}

/// A public key from one parameter set must be rejected by another, both as-is
/// (caught by the length check) and re-cut to the target's key length (so the
/// test still means something if the length gate ever changes).
#[test]
fn public_key_from_another_param_set_is_rejected() {
    let message = b"cross-parameter-set confusion";
    for ps in ParamSet::ALL {
        let (pk, sk) = pqkey_mldsa::keypair(ps);
        let sig = try_sign(ps, &sk, message).expect("sign");
        assert!(verify(ps, &pk, message, &sig), "{ps} sanity check");

        for other in other_param_sets(ps) {
            let (other_pk_len, _sk_len, other_sig_len) = lengths(other);

            // As-is: different parameter sets have different key and
            // signature lengths, so this is refused outright.
            assert!(
                !verify(other, &pk, message, &sig),
                "{ps} public key accepted by {other}"
            );

            // Re-cut to the target's lengths so the length gate cannot be the
            // only thing doing the work.
            let mut resized_pk = pk.as_bytes().to_vec();
            resized_pk.resize(other_pk_len, 0);
            let mut resized_sig = sig.clone();
            resized_sig.resize(other_sig_len, 0);
            assert!(
                !verify(other, &PublicKey::new(resized_pk), message, &resized_sig),
                "{ps} public key accepted by {other} after resizing"
            );
        }
    }
}

/// A secret key from one parameter set must not be usable to sign under
/// another; the wrapper must report the length mismatch rather than produce
/// something that looks like a signature.
#[test]
fn secret_key_from_another_param_set_is_rejected() {
    for ps in ParamSet::ALL {
        let (_pk, sk) = pqkey_mldsa::keypair(ps);
        for other in other_param_sets(ps) {
            assert_eq!(
                try_sign(other, &sk, b"msg"),
                Err(MlDsaError::InvalidKeyLength),
                "{ps} secret key accepted by {other}"
            );
            assert!(
                pqkey_mldsa::sign(other, &sk, b"msg").is_empty(),
                "{ps} secret key produced a signature under {other}"
            );
        }
    }
}

/// The same confusion check, but with NIST's own key material rather than
/// freshly generated keys.
#[test]
fn nist_signatures_do_not_cross_param_sets() {
    for case in parse(SIGGEN_KAT) {
        let label = case.label();
        let ps = case.param_set();
        let pk = PublicKey::new(case.bytes("pk"));
        let ctx = case.bytes("context");
        let message = case.bytes("message");
        let signature = case.bytes("signature");

        for other in other_param_sets(ps) {
            assert!(
                !verify_with_context(other, &pk, &message, &signature, &ctx),
                "{label}: verified under {other}"
            );
        }
    }
}

/// `sign()` reports failure only by returning an empty `Vec` — the hazard
/// documented on the function.  Pin that behaviour so nobody "fixes" it into
/// something that looks like a signature.
#[test]
fn sign_reports_failure_as_an_empty_vec() {
    let ps = ParamSet::MLDSA44;
    let junk = SecretKey::new(vec![0u8; 7]);
    let sig = pqkey_mldsa::sign(ps, &junk, b"msg");
    assert!(sig.is_empty(), "sign() must return an empty Vec on failure");
    assert_ne!(sig.len(), lengths(ps).2);

    // ... and a caller that only checks emptiness is not fooled by a real one.
    let (_pk, sk) = pqkey_mldsa::keypair(ps);
    assert_eq!(pqkey_mldsa::sign(ps, &sk, b"msg").len(), lengths(ps).2);
}
