//! CTAPHID framing; see `authenticator_fuzz::ctaphid` for the invariants.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| authenticator_fuzz::ctaphid::run(data));
