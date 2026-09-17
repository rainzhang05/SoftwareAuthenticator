//! Shared harness for the fuzz targets: a deterministic engine, the checks
//! every CTAP response must pass, a structure-aware CTAP request generator,
//! the platform side of the PIN/UV auth protocols, and the bodies of the
//! targets, so the seed corpus generator (`examples/seeds.rs`) can drive
//! them too.

pub mod cbor;
pub mod ctaphid;
pub mod engine;
pub mod platform;
pub mod requests;
pub mod rng;
pub mod sequence;
pub mod structured;
