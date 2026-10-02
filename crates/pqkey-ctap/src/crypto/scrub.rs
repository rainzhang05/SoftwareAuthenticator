//! Stack scrubbing around secret-dependent arithmetic.

use zeroize::Zeroize;

/// Run `operation`, which handles a P-256 private key, then overwrite the
/// stack it used.
///
/// RustCrypto's `ecdsa` and `elliptic-curve` wipe their key types on drop but
/// leave intermediates in plain locals, among them an ECDSA signature's
/// nonce `k`, which together with the signature reveals the private key.
/// They stay in the stack after the call returns.  `operation` therefore runs
/// in a frame of its own below the caller, and the 64 KiB below the caller
/// are then filled with zeros, many times what ES256 signing and key
/// generation use (`tests/residue.rs` found `k` 3 KiB down).  `zeroize`
/// writes with volatile stores the compiler may not remove.
pub(crate) fn with_scrubbed_stack<T>(operation: impl FnOnce() -> T) -> T {
    let result = run_below(operation);
    scrub_stack();
    result
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
