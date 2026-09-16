//! The pinUvAuthToken and its state variables (CTAP 2.3 §6.5.2.1), managed by
//! the maintenance functions of §6.5.3.2, with an injectable clock.

use core::time::Duration;
#[cfg(test)]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

#[cfg(test)]
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::protocol::{verify, PinProtocol};

use crate::ctap::constants::*;

/// "initial usage time limit": "The platform MUST invoke an authenticator
/// operation using the pinUvAuthToken within this time limit for the
/// pinUvAuthToken to remain valid for the full max usage time period."  The
/// default maximum for usb is 30 seconds (CTAP 2.3 §6.5.2.1).
pub(crate) const INITIAL_USAGE_TIME_LIMIT: Duration = Duration::from_secs(30);

/// "user present time limit", which "defaults to the same default maximum
/// per-transport values as the initial usage time limit" (CTAP 2.3 §6.5.2.1).
pub(crate) const USER_PRESENT_TIME_LIMIT: Duration = Duration::from_secs(30);

/// "max usage time period value, which SHOULD default to a maximum of 10
/// minutes (600 seconds)" (CTAP 2.3 §6.5.2.1).
pub(crate) const MAX_USAGE_TIME_PERIOD: Duration = Duration::from_secs(600);

/// lbw, the one permission that survives a user presence test (CTAP 2.3
/// §6.5.5.7).  This authenticator never grants it.
const PIN_PERMISSION_LBW: u8 = 0x10;

/// A monotonic time source for the pinUvAuthToken usage timer.
pub(crate) trait Clock: Send + Sync {
    /// Time elapsed since an arbitrary, fixed origin.
    fn now(&self) -> Duration;
}

/// The system's monotonic clock.
pub(crate) struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A clock tests move by hand; clones share the same time.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct ManualClock {
    now_ms: Arc<AtomicU64>,
}

#[cfg(test)]
impl ManualClock {
    pub(crate) fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).expect("duration fits");
        self.now_ms.fetch_add(by, Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.now_ms.load(Ordering::SeqCst))
    }
}

/// An in-use pinUvAuthToken and its state variables.
///
/// "Each PIN/UV auth protocol maintains its own pinUvAuthToken" (§6.5), and
/// issuing one resets the tokens of all protocols, so only the token of the
/// protocol it was issued over is known to the platform.  Recording that
/// protocol and refusing verification under the other is equivalent to
/// holding a second, never-disclosed random token for it.
#[derive(Zeroize, ZeroizeOnDrop)]
struct InUseToken {
    value: [u8; 32],
    #[zeroize(skip)]
    protocol: PinProtocol,
    permissions: u8,
    permissions_rp_id: Option<String>,
    #[zeroize(skip)]
    started_at: Duration,
    /// The platform has used the token within the initial usage time limit.
    used: bool,
    user_present: bool,
    user_verified: bool,
}

/// The pinUvAuthToken state.  `None` is "not in use": every state variable at
/// its initial value, so the token verifies nothing.
#[derive(Default)]
pub(crate) struct PinUvAuthTokenState {
    in_use: Option<InUseToken>,
}

impl PinUvAuthTokenState {
    /// `resetPinUvAuthToken()` for all protocols followed by
    /// `beginUsingPinUvAuthToken(userIsPresent)`: "Set the userPresent flag to
    /// the value of userIsPresent. Set the userVerified flag to true. [...]
    /// Start the pinUvAuthToken usage timer, set the in use flag to true"
    /// (CTAP 2.3 §6.5.3.2), then assign the permissions and, if given, the
    /// permissions RP ID (§6.5.5.7.1, §6.5.5.7.2).
    pub(crate) fn begin_using(
        &mut self,
        now: Duration,
        protocol: PinProtocol,
        value: [u8; 32],
        user_is_present: bool,
        permissions: u8,
        permissions_rp_id: Option<String>,
    ) {
        self.in_use = Some(InUseToken {
            value,
            protocol,
            permissions,
            permissions_rp_id,
            started_at: now,
            used: false,
            user_present: user_is_present,
            user_verified: true,
        });
    }

    /// `stopUsingPinUvAuthToken()`: "Set all of the pinUvAuthToken's state
    /// variables to their initial values".
    pub(crate) fn stop_using(&mut self) {
        self.in_use = None;
    }

    /// `pinUvAuthTokenUsageTimerObserver()`, evaluated whenever the token is
    /// looked at rather than from a background timer:
    ///
    /// * "If the current user present time limit is reached, call
    ///   clearUserPresentFlag()."
    /// * "If the initial usage time limit is reached without the platform
    ///   using the pinUvAuthToken in an authenticator operation then call
    ///   stopUsingPinUvAuthToken()".
    /// * Once the max usage time period is reached, "Call
    ///   stopUsingPinUvAuthToken()".
    ///
    /// The optional rolling timer is not used, so a token that was used in
    /// time stays valid for the whole max usage time period.
    pub(crate) fn observe(&mut self, now: Duration) {
        let Some(token) = self.in_use.as_mut() else {
            return;
        };
        let elapsed = now.saturating_sub(token.started_at);
        if elapsed >= MAX_USAGE_TIME_PERIOD || (!token.used && elapsed >= INITIAL_USAGE_TIME_LIMIT)
        {
            self.stop_using();
            return;
        }
        if elapsed >= USER_PRESENT_TIME_LIMIT {
            token.user_present = false;
        }
    }

    /// `verify(pinUvAuthToken, message, signature)`: "If the key parameter
    /// value is the current pinUvAuthToken and it is not in use, then return
    /// error." (CTAP 2.3 §6.5.6, §6.5.7)  A successful verification is the
    /// platform using the token in an authenticator operation.
    pub(crate) fn verify(
        &mut self,
        now: Duration,
        protocol: PinProtocol,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), u8> {
        self.observe(now);
        let token = self.in_use.as_mut().ok_or(CTAP2_ERR_PIN_AUTH_INVALID)?;
        if token.protocol != protocol {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        verify(protocol, &token.value, message, signature)?;
        token.used = true;
        Ok(())
    }

    /// `getUserPresentFlagValue()`: the userPresent flag if the token is in
    /// use, otherwise false.  No issuance path of this authenticator collects
    /// user presence, so it is only ever set by tests.
    #[cfg(test)]
    pub(crate) fn user_present_flag(&mut self, now: Duration) -> bool {
        self.observe(now);
        self.in_use.as_ref().is_some_and(|token| token.user_present)
    }

    /// `getUserVerifiedFlagValue()`: the userVerified flag if the token is in
    /// use, otherwise false.
    pub(crate) fn user_verified_flag(&mut self, now: Duration) -> bool {
        self.observe(now);
        self.in_use
            .as_ref()
            .is_some_and(|token| token.user_verified)
    }

    /// `clearUserPresentFlag()`, `clearUserVerifiedFlag()` and
    /// `clearPinUvAuthTokenPermissionsExceptLbw()`, as authenticatorMakeCredential
    /// (§6.1.2 step 14) and authenticatorGetAssertion (§6.2.2 step 9) call them
    /// after collecting user presence.  "These functions are no-ops if there
    /// is not an in-use pinUvAuthToken."
    pub(crate) fn consume_after_user_presence(&mut self, now: Duration) {
        self.observe(now);
        if let Some(token) = self.in_use.as_mut() {
            token.user_present = false;
            token.user_verified = false;
            token.permissions &= PIN_PERMISSION_LBW;
        }
    }

    pub(crate) fn has_permission(&mut self, now: Duration, permission: u8) -> bool {
        self.observe(now);
        self.in_use
            .as_ref()
            .is_some_and(|token| token.permissions & permission != 0)
    }

    #[cfg(test)]
    pub(crate) fn permissions(&mut self, now: Duration) -> u8 {
        self.observe(now);
        self.in_use.as_ref().map_or(0, |token| token.permissions)
    }

    pub(crate) fn permissions_rp_id(&mut self, now: Duration) -> Option<&str> {
        self.observe(now);
        self.in_use
            .as_ref()
            .and_then(|token| token.permissions_rp_id.as_deref())
    }

    /// "If the pinUvAuthToken does not have a permissions RP ID associated:
    /// Associate the request's rp.id parameter value with the pinUvAuthToken
    /// as its permissions RP ID." (§6.1.2 step 11.1.6, §6.2.2 step 6.1.7)
    pub(crate) fn bind_permissions_rp_id(&mut self, now: Duration, rp_id: &str) {
        self.observe(now);
        if let Some(token) = self.in_use.as_mut() {
            if token.permissions_rp_id.is_none() {
                token.permissions_rp_id = Some(rp_id.to_string());
            }
        }
    }

    /// The token value, while in use.
    #[cfg(test)]
    pub(crate) fn value(&mut self, now: Duration) -> Option<Zeroizing<[u8; 32]>> {
        self.observe(now);
        self.in_use
            .as_ref()
            .map(|token| Zeroizing::new(token.value))
    }
}
