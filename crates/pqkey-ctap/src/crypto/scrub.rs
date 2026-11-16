//! Stack scrubbing around secret-dependent arithmetic.

use zeroize::Zeroize;

/// Run `operation`, which handles a private key or key agreement secret,
/// then overwrite the stack it used.
///
/// RustCrypto's `ecdsa` and `elliptic-curve` wipe their key types on drop but
/// leave intermediates in plain locals, among them an ECDSA signature's nonce
/// `k`, which together with the signature reveals the private key.
/// ed25519-dalek and ed448-goldilocks do the same with the hash of an EdDSA
/// private key and a signature's nonce `r`.  They stay in the stack after the
/// call returns.  `operation` therefore runs in a frame of its own below the
/// caller, and the 64 KiB below the caller are then filled with zeros, many
/// times what ECDSA and EdDSA key derivation and signing use
/// (`tests/residue.rs` found `k`, or what it was drawn from, up to 6 KiB down,
/// for P-521 in a release build, and Ed25519's `r` about 1 KiB down).
/// `zeroize` writes with volatile stores the compiler may not remove.
///
/// The result is `run_below`'s, passed on as this function's own: it is
/// stored where the caller asked for it before the scrub runs, so no copy of
/// it stays in this frame, above the zeroed stack, such as of a key that
/// [`try_credential_secret_from_bytes`] reads.  A caller that returns a
/// secret from here passes it on the same way, as its tail expression.  A
/// result small enough to come back in registers, 16 bytes or less, can be
/// saved to the stack around the scrub instead; no secret here is that small.
///
/// [`try_credential_secret_from_bytes`]: crate::try_credential_secret_from_bytes
pub(crate) fn with_scrubbed_stack<T>(operation: impl FnOnce() -> T) -> T {
    struct ScrubOnExit;
    impl Drop for ScrubOnExit {
        fn drop(&mut self) {
            scrub_stack();
        }
    }
    // Dropped, scrubbing the stack, once the tail expression has stored the
    // result.
    let _scrub = ScrubOnExit;
    run_below(operation)
}

/// `operation()` in a frame of its own; see [`with_scrubbed_stack`].
#[inline(never)]
fn run_below<T>(operation: impl FnOnce() -> T) -> T {
    operation()
}

/// Overwrite the 64 KiB of stack below the caller with zeros.
#[inline(never)]
fn scrub_stack() {
    let mut words = [0u64; 64 * 1024 / 8];
    words.zeroize();
    core::hint::black_box(&words);
}
