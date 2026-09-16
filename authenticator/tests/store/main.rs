//! Tests of `authenticator::store` through its public API.
//!
//! `conformance` runs one suite of cases, generic over `CredentialStore`,
//! against every implementation, so the in-memory store the CTAP engine is
//! tested with cannot drift from the file store it runs with.

mod common;
mod conformance;
