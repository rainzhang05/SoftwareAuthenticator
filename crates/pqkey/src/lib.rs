// The allocator wipes owned memory and the uhid device reads and writes
// kernel structures through `unsafe`; each block says why it is sound.
#![warn(clippy::undocumented_unsafe_blocks)]

#[cfg(not(target_os = "linux"))]
compile_error!("pqkey requires Linux; pqkey-ctap and pqkey-mldsa are portable");

#[cfg(target_os = "linux")]
pub mod allocator;
#[cfg(target_os = "linux")]
pub mod attestation;
#[cfg(target_os = "linux")]
pub mod cli;
#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
pub mod pin_input;
#[cfg(target_os = "linux")]
pub mod platform;
#[cfg(target_os = "linux")]
pub mod presence;
#[cfg(target_os = "linux")]
pub mod service;
#[cfg(target_os = "linux")]
pub mod shutdown;
#[cfg(target_os = "linux")]
pub mod state;
#[cfg(target_os = "linux")]
pub mod state_lock;
#[cfg(target_os = "linux")]
pub mod transport;

#[cfg(all(test, target_os = "linux"))]
mod test_support;

#[cfg(target_os = "linux")]
pub use platform::create_device;
#[cfg(target_os = "linux")]
pub use transport::{
    App, CAPABILITY_CBOR, CAPABILITY_NMSG, MESSAGE_SIZE, Transport, WaitingForUser, exec, serve,
};
