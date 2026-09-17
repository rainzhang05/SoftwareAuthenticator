//! Stateful CTAP request sequences; see `authenticator_fuzz::sequence` for
//! the invariants.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| authenticator_fuzz::sequence::run(data));
