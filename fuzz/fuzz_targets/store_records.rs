//! The credential store's record decoders: `store/codec.rs`'s five record
//! decoders, the credential-set manifest's and `envelope::open`, through
//! `pqkey_ctap::store::fuzzing::check`.
//!
//! Records are decoded only after their envelope authenticates, so the
//! realistic sources of bad ones are a buggy writer and a key holder; the
//! envelope is parsed before that.  Either way "a corrupted or truncated
//! record must produce an error, never a panic".  Invariants: no panic; a
//! record or manifest that decodes encodes again into one that decodes to an
//! equal value; and no envelope opens under a key it was not sealed with.
//!
//! Input layout: the object (byte 0, an index into
//! `pqkey_ctap::store::fuzzing::Object::ALL`), then the bytes to decode as
//! it.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| pqkey_fuzz::store_records::run(data));
