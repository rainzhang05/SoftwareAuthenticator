//! Turning SIGINT and SIGTERM into an orderly stop of the daemon.
//!
//! The signal handler only sets a flag. The uhid transport checks the flag on
//! every pass through the daemon loop ([`crate::serve`]) and then fails with
//! [`shutdown_error`]. That ends the loop: the app and the transport are
//! dropped (which destroys the uhid device) and the error comes back out,
//! where [`ok_if_shutdown`] turns it into a successful exit.

use std::{
    error::Error,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use signal_hook::{
    consts::{SIGINT, SIGTERM},
    flag,
};

/// Shared flag that is set once the daemon has been asked to stop.
#[derive(Clone, Debug, Default)]
pub struct ShutdownSignal(Arc<AtomicBool>);

impl ShutdownSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request shutdown when SIGINT or SIGTERM arrives. If a second one
    /// arrives while shutdown is under way, the process is terminated
    /// immediately, in case the orderly path is stuck.
    pub fn install_signal_handlers(&self) -> io::Result<()> {
        for signal in [SIGINT, SIGTERM] {
            // Actions run in registration order, so this one only sees the
            // flag set by an earlier signal.
            flag::register_conditional_default(signal, Arc::clone(&self.0))?;
            flag::register(signal, Arc::clone(&self.0))?;
        }
        Ok(())
    }

    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Fail with [`shutdown_error`] once shutdown has been requested.
    pub fn check(&self) -> io::Result<()> {
        if self.is_requested() {
            Err(shutdown_error())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct ShutdownRequested;

impl fmt::Display for ShutdownRequested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("shutdown requested")
    }
}

impl Error for ShutdownRequested {}

/// The error the transport returns to stop the runner loop.
pub fn shutdown_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, ShutdownRequested)
}

/// Whether `err` is [`shutdown_error`], as opposed to any other interrupted
/// or failed operation.
pub fn is_shutdown(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
        && err
            .get_ref()
            .is_some_and(|inner| inner.is::<ShutdownRequested>())
}

/// Treat a requested shutdown as success and pass everything else through.
pub fn ok_if_shutdown(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(err) if is_shutdown(&err) => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn check_fails_only_after_a_request() {
        let shutdown = ShutdownSignal::new();
        assert!(shutdown.check().is_ok());
        shutdown.clone().request();
        let err = shutdown.check().unwrap_err();
        assert!(is_shutdown(&err));
    }

    #[test]
    fn only_the_shutdown_error_counts_as_a_clean_exit() {
        assert!(ok_if_shutdown(Ok(())).is_ok());
        assert!(ok_if_shutdown(Err(shutdown_error())).is_ok());

        let other_interruptions = [
            io::Error::from(io::ErrorKind::Interrupted),
            io::Error::new(io::ErrorKind::Interrupted, "shutdown requested"),
            io::Error::from_raw_os_error(nix::libc::EINTR),
        ];
        for err in other_interruptions {
            assert!(!is_shutdown(&err), "{err:?}");
            assert!(ok_if_shutdown(Err(err)).is_err());
        }
        assert!(ok_if_shutdown(Err(io::Error::other("device gone"))).is_err());
    }

    #[test]
    fn sigterm_requests_shutdown_instead_of_terminating() {
        let _serialized = test_support::lock_signal_handlers();
        let shutdown = ShutdownSignal::new();
        shutdown.install_signal_handlers().unwrap();
        assert!(!shutdown.is_requested());

        // Delivered to this thread before `raise` returns. Without the handler
        // (or with the handlers registered in the wrong order) this would
        // terminate the test process.
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).unwrap();
        assert!(shutdown.is_requested());
        assert!(is_shutdown(&shutdown.check().unwrap_err()));
    }
}
