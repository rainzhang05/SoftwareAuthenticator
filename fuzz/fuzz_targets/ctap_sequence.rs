//! Stateful CTAP request sequences; see `pqkey_fuzz::sequence` for
//! the invariants.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| pqkey_fuzz::sequence::run(data));
