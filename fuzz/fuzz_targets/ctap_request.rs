//! One CTAPHID_CBOR message, the input exactly as a platform would send it
//! (command byte, then CBOR parameters), to a fresh engine over an empty
//! in-memory store whose user approves everything.
//!
//! Invariants (see `authenticator_fuzz::engine::check_response`): no panic;
//! the response fits the 7,609-byte buffer, so the platform gets a CTAP status
//! rather than a CTAPHID error; its first byte is a status code CTAP defines;
//! an error status carries nothing else; and a success carries nothing or
//! exactly one CBOR map.

#![no_main]

use authenticator_fuzz::engine::Engine;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut engine = Engine::new(0);
    engine.call(data);
});
