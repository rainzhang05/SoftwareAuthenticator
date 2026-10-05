// The allocator wipes owned memory and the uhid device reads and writes
// kernel structures through `unsafe`; each block says why it is sound.
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod allocator;
pub mod attestation;
pub mod cli;
pub mod client;
pub(crate) use platform::linux::clock;
pub mod platform;
pub use platform::linux::permissions;
pub mod pin_input;
pub mod presence;
pub mod service;
pub mod shutdown;
pub mod state;
pub mod state_lock;
pub mod transport;
pub use platform::linux::uhid;

#[cfg(test)]
mod test_support;

pub use transport::{
    App, CAPABILITY_CBOR, CAPABILITY_NMSG, MESSAGE_SIZE, UhidTransport, WaitingForUser,
    create_device, exec, serve,
};
use uhid::HidDeviceDescriptor;

#[cfg(test)]
pub(crate) use transport::tests;
