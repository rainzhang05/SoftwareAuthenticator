//! How the daemon asks the user to approve an operation.
//!
//! The CTAP engine asks a [`UserPresence`] implementation whenever an
//! operation needs evidence of user interaction; [`PresenceMode`] selects the
//! one the daemon runs with.

use std::{
    thread,
    time::{Duration, Instant},
};

use pqkey_ctap::ctap::presence::{Cancellation, PresenceOutcome, PresenceRequest, UserPresence};

pub mod dbus;
pub mod notification;

/// How often waiting implementations look at their [`Cancellation`].
pub(crate) const CANCELLATION_POLL: Duration = Duration::from_millis(20);

/// The `--presence` modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceMode {
    /// Ask with a desktop notification
    /// ([`NotificationPresence`](notification::NotificationPresence)).
    Notify,
    /// Approve every request without asking anyone. For tests and CI only.
    AutoApprove,
    /// Never answer: wait until the request is cancelled or times out. For
    /// tests of the transport while a prompt is showing.
    Unanswered,
}

/// Leaves every request unanswered until the platform cancels it or its
/// timeout passes, as a user who ignores the prompt would.
///
/// Tests use it to watch the transport while the authenticator waits for the
/// user: "user presence needed" keepalives, CTAPHID_CANCEL, and other channels
/// being told the device is busy.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unanswered;

impl UserPresence for Unanswered {
    fn confirm(
        &mut self,
        request: &PresenceRequest<'_>,
        cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        let deadline = Instant::now() + request.timeout;
        loop {
            if cancellation.is_cancelled() {
                return PresenceOutcome::Cancelled;
            }
            let now = Instant::now();
            if now >= deadline {
                return PresenceOutcome::TimedOut;
            }
            thread::sleep(CANCELLATION_POLL.min(deadline - now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqkey_ctap::ctap::{InterruptFlag, presence::PresenceOperation};

    #[test]
    fn unanswered_times_out() {
        let flag = InterruptFlag::new();
        flag.set_working();
        let request = PresenceRequest::new(PresenceOperation::Register, Duration::from_millis(50));
        let started = Instant::now();
        let outcome = Unanswered.confirm(&request, Cancellation::new(&flag));
        assert_eq!(outcome, PresenceOutcome::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn unanswered_returns_promptly_once_cancelled() {
        let flag = InterruptFlag::new();
        flag.set_working();
        let request = PresenceRequest::new(PresenceOperation::Reset, Duration::from_secs(60));
        let started = Instant::now();
        let outcome = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(100));
                flag.interrupt();
            });
            Unanswered.confirm(&request, Cancellation::new(&flag))
        });
        assert_eq!(outcome, PresenceOutcome::Cancelled);
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
