//! User presence: asking the user to approve an operation.
//!
//! The engine never concludes on its own that a user is present.  For every
//! operation that needs evidence of user interaction it describes the
//! operation in a [`PresenceRequest`] and asks the [`UserPresence`]
//! implementation it was constructed with.  The implementation answers with a
//! [`PresenceOutcome`], and the engine turns anything but
//! [`PresenceOutcome::Approved`] into the CTAP status the specification
//! prescribes for that operation.  While it waits, the transport is told to
//! send "user presence needed" keepalives.
//!
//! [`AutoApprove`] approves every request immediately.

use std::time::Duration;

use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use trussed_core::InterruptFlag;

use super::CtapApp;
use crate::ctap::constants::*;

/// How long a presence request waits for the user unless configured
/// otherwise.  CTAP 2.3 §5 requires a user action timeout of at least 10
/// seconds and calls 30 seconds a reasonable value.
pub const DEFAULT_PRESENCE_TIMEOUT: Duration = Duration::from_secs(30);

/// What the user is asked to approve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PresenceOperation {
    /// authenticatorMakeCredential: create a credential for the relying party.
    Register,
    /// authenticatorGetAssertion: sign in to the relying party.
    Authenticate,
    /// authenticatorReset: erase every credential and the PIN.
    Reset,
    /// authenticatorCredentialManagement.  CTAP 2.3 §6.8 does not require user
    /// presence for it and the engine does not ask for it today; the variant
    /// exists so implementations can already describe such a request.
    CredentialManagement,
}

/// A request for the user to approve one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresenceRequest<'a> {
    /// The operation to approve.
    pub operation: PresenceOperation,
    /// The relying party the operation is for, if there is one, so a prompt
    /// can say "Sign in to example.com".
    pub rp_id: Option<&'a str>,
    /// `user.name` of the account a new credential is for, when registering.
    pub user_name: Option<&'a str>,
    /// `user.displayName` of the account a new credential is for, when
    /// registering.
    pub user_display_name: Option<&'a str>,
    /// How long to wait for the user before answering
    /// [`PresenceOutcome::TimedOut`].
    pub timeout: Duration,
}

impl PresenceRequest<'_> {
    /// A request for `operation` with no relying party or user details.
    #[must_use]
    pub const fn new(operation: PresenceOperation, timeout: Duration) -> Self {
        Self {
            operation,
            rp_id: None,
            user_name: None,
            user_display_name: None,
            timeout,
        }
    }
}

/// How a presence request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceOutcome {
    /// The user approved the operation.
    Approved,
    /// The user refused the operation.
    Denied,
    /// The user did not answer within [`PresenceRequest::timeout`].
    TimedOut,
    /// The platform cancelled the request (CTAPHID_CANCEL) before the user
    /// answered.
    Cancelled,
}

/// Lets a [`UserPresence`] implementation notice that the platform cancelled
/// the request it is waiting on.
#[derive(Clone, Copy, Debug)]
pub struct Cancellation<'a> {
    flag: &'a InterruptFlag,
}

impl<'a> Cancellation<'a> {
    /// Observe `flag`, the interrupt flag the CTAPHID dispatcher marks when a
    /// CTAPHID_CANCEL arrives for the request being processed.
    #[must_use]
    pub fn new(flag: &'a InterruptFlag) -> Self {
        Self { flag }
    }

    /// Whether the platform has cancelled the request.  An implementation that
    /// waits for the user should check this regularly, every 100 ms or so, and
    /// answer [`PresenceOutcome::Cancelled`] once it is true.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.is_interrupted()
    }
}

/// Asks the user to approve operations.
pub trait UserPresence {
    /// Ask the user to approve `request`, and block until they answer,
    /// `request.timeout` elapses, or `cancellation` reports that the platform
    /// cancelled the request.
    fn confirm(
        &mut self,
        request: &PresenceRequest<'_>,
        cancellation: Cancellation<'_>,
    ) -> PresenceOutcome;
}

/// Approves every request immediately, without involving the user.
///
/// This gives no protection against software on the machine using the
/// authenticator without the user's knowledge; it exists until a prompt that
/// asks the user is available.
#[derive(Clone, Copy, Debug, Default)]
pub struct AutoApprove;

impl UserPresence for AutoApprove {
    fn confirm(
        &mut self,
        _request: &PresenceRequest<'_>,
        _cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        PresenceOutcome::Approved
    }
}

/// The CTAP status for `outcome` of a presence request for `operation`.
///
/// * Denied: CTAP2_ERR_OPERATION_DENIED for every operation (CTAP 2.3 §6.1.2
///   step 14.2.1.2, §6.2.2 step 9.2.1.2, §6.6).
/// * Timed out: makeCredential and getAssertion return
///   CTAP2_ERR_OPERATION_DENIED, because the same steps read "If the user
///   declines permission, or the operation times out, then end the operation
///   by returning CTAP2_ERR_OPERATION_DENIED".  authenticatorReset returns
///   CTAP2_ERR_USER_ACTION_TIMEOUT (§6.6), and so does credential management,
///   for which §6.8 defines no presence step, following the definition of a
///   user action timeout in §5.
/// * Cancelled: CTAP2_ERR_KEEPALIVE_CANCEL (§11.2.9.1.5, CTAPHID_CANCEL).
pub(super) fn presence_status(
    operation: PresenceOperation,
    outcome: PresenceOutcome,
) -> Result<(), u8> {
    match outcome {
        PresenceOutcome::Approved => Ok(()),
        PresenceOutcome::Denied => Err(CTAP2_ERR_OPERATION_DENIED),
        PresenceOutcome::TimedOut => match operation {
            PresenceOperation::Register | PresenceOperation::Authenticate => {
                Err(CTAP2_ERR_OPERATION_DENIED)
            }
            PresenceOperation::Reset | PresenceOperation::CredentialManagement => {
                Err(CTAP2_ERR_USER_ACTION_TIMEOUT)
            }
        },
        PresenceOutcome::Cancelled => Err(CTAP2_ERR_KEEPALIVE_CANCEL),
    }
}

/// Reports "waiting for the user" to the keepalive callback while alive, and
/// clears it when dropped, even if the presence implementation panics.
struct WaitingForUser<'a> {
    keepalive: &'a mut (dyn FnMut(bool) + Send),
}

impl<'a> WaitingForUser<'a> {
    fn begin(keepalive: &'a mut (dyn FnMut(bool) + Send)) -> Self {
        keepalive(true);
        Self { keepalive }
    }
}

impl Drop for WaitingForUser<'_> {
    fn drop(&mut self) {
        (self.keepalive)(false);
    }
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    /// Ask for evidence of user interaction, and return the CTAP status for
    /// anything but approval.  A request the platform has already cancelled
    /// is never shown to the user.
    pub(super) fn confirm_user_presence(&mut self, request: PresenceRequest<'_>) -> Result<(), u8> {
        let cancellation = Cancellation::new(self.interrupt);
        let outcome = if cancellation.is_cancelled() {
            PresenceOutcome::Cancelled
        } else {
            let _waiting = WaitingForUser::begin(&mut *self.keepalive);
            self.presence.confirm(&request, cancellation)
        };
        presence_status(request.operation, outcome)
    }
}
