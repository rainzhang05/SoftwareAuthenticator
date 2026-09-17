//! Structure-aware CTAP requests; see `pqkey_fuzz::structured` for
//! the invariants.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| pqkey_fuzz::structured::run(data));
