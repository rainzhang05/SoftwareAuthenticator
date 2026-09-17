//! CTAPHID framing; see `pqkey_fuzz::ctaphid` for the invariants.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| pqkey_fuzz::ctaphid::run(data));
