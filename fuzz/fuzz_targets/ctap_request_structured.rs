//! Structure-aware CTAP requests; see `authenticator_fuzz::structured` for
//! the invariants.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| authenticator_fuzz::structured::run(data));
