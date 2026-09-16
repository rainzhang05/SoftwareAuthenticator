//! The PIN retry state machine and the current pinUvAuthToken.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use transport_core::ctap::constants::*;

/// The maximum, and initial, value of pinRetries: "Authenticators MUST allow no
/// more than 8 retries but MAY set a lower maximum." (CTAP 2.3 §6.5.2.3)
pub const MAX_PIN_RETRIES: u8 = 8;

/// "If the authenticator sees 3 consecutive mismatches, it returns
/// CTAP2_ERR_PIN_AUTH_BLOCKED, indicating that power cycling is needed for
/// further operations." (CTAP 2.3 §6.5.5.6, §6.5.5.7.1, §6.5.5.7.2)
pub const MAX_CONSECUTIVE_PIN_MISMATCHES: u8 = 3;

/// The part of the PIN state that must survive a power cycle.
///
/// pinRetries has to be persistent: once it "reaches 0, both ClientPin as well
/// as built-in user verification are disabled and can only be enabled if the
/// authenticator is reset" (CTAP 2.3 §6.5.2.3), which a power cycle is not.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PersistentPinState {
    /// CurrentStoredPIN, `LEFT(SHA-256(PIN), 16)`, or `None` if no PIN is set.
    pub pin_hash: Option<[u8; 16]>,
    /// pinRetries.
    pub pin_retries: u8,
}

impl Default for PersistentPinState {
    fn default() -> Self {
        Self {
            pin_hash: None,
            pin_retries: MAX_PIN_RETRIES,
        }
    }
}

impl fmt::Debug for PersistentPinState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentPinState")
            .field("pin_hash", &self.pin_hash.map(|_| "<redacted>"))
            .field("pin_retries", &self.pin_retries)
            .finish()
    }
}

/// The PIN retry state machine of CTAP 2.3 §6.5.2.3, as driven by the PIN
/// checks of changePIN (§6.5.5.6), getPinToken (§6.5.5.7.1) and
/// getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2).
///
/// It performs no I/O, so anything that verifies a PIN against the stored hash
/// can share it.  A check is split in two, mirroring the spec's steps:
///
/// 1. [`begin_attempt`](Self::begin_attempt) refuses the attempt if the PIN is
///    blocked ("If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED
///    error.") or needs a power cycle, and otherwise "decrements the pinRetries
///    counter by 1".
/// 2. The caller persists [`persistent`](Self::persistent).
/// 3. [`finish_attempt`](Self::finish_attempt) compares the candidate hash.
///
/// Persisting between the two steps means cutting power while the PIN is being
/// compared cannot give an attacker a free guess.  The consecutive-mismatch
/// count behind CTAP2_ERR_PIN_AUTH_BLOCKED is volatile on purpose: it exists so
/// "malware running on the platform should not be able to block the device
/// without user interaction", and a power cycle is that interaction.
pub struct PinRetryState {
    persistent: PersistentPinState,
    consecutive_mismatches: u8,
}

/// A PIN retry that [`PinRetryState::begin_attempt`] has already consumed.
/// Only this proof lets a candidate PIN hash be compared.
#[must_use = "finish the attempt with PinRetryState::finish_attempt"]
pub struct PinAttempt(());

impl Default for PinRetryState {
    /// An authenticator with no PIN set.
    fn default() -> Self {
        Self::power_up(PersistentPinState::default())
    }
}

impl PinRetryState {
    /// The state after power-up: the persistent part as it was last stored,
    /// and no consecutive mismatches.  A stored pinRetries above
    /// [`MAX_PIN_RETRIES`] is clamped to it.
    pub fn power_up(mut persistent: PersistentPinState) -> Self {
        persistent.pin_retries = persistent.pin_retries.min(MAX_PIN_RETRIES);
        Self {
            persistent,
            consecutive_mismatches: 0,
        }
    }

    /// What has to be written to persistent storage.
    pub fn persistent(&self) -> &PersistentPinState {
        &self.persistent
    }

    pub fn is_set(&self) -> bool {
        self.persistent.pin_hash.is_some()
    }

    pub fn retries(&self) -> u8 {
        self.persistent.pin_retries
    }

    /// Whether PIN checks are refused until the next power-up; this is the
    /// getPINRetries powerCycleState (CTAP 2.3 §6.5.5).
    pub fn power_cycle_required(&self) -> bool {
        self.consecutive_mismatches >= MAX_CONSECUTIVE_PIN_MISMATCHES
    }

    /// Store a new PIN: "stores LEFT(SHA-256(newPin), 16) internally as
    /// CurrentStoredPIN, sets the pinRetries counter to maximum count"
    /// (CTAP 2.3 §6.5.5.5, §6.5.5.6).
    pub fn set_pin(&mut self, pin_hash: [u8; 16]) {
        self.persistent.pin_hash = Some(pin_hash);
        self.persistent.pin_retries = MAX_PIN_RETRIES;
        self.consecutive_mismatches = 0;
    }

    /// Whether a PIN check may start, without consuming a retry.
    ///
    /// * `CTAP2_ERR_PIN_NOT_SET` if there is no PIN to check against.
    /// * `CTAP2_ERR_PIN_BLOCKED` if pinRetries is 0; the PIN is not compared,
    ///   so even the correct PIN is refused until a reset.
    /// * `CTAP2_ERR_PIN_AUTH_BLOCKED` if a power cycle is required.
    pub fn check_attempt_allowed(&self) -> Result<(), u8> {
        if !self.is_set() {
            Err(CTAP2_ERR_PIN_NOT_SET)
        } else if self.persistent.pin_retries == 0 {
            Err(CTAP2_ERR_PIN_BLOCKED)
        } else if self.power_cycle_required() {
            Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
        } else {
            Ok(())
        }
    }

    /// Consume one retry ahead of comparing a PIN.  The decremented
    /// [`persistent`](Self::persistent) state must be stored before
    /// [`finish_attempt`](Self::finish_attempt) is called.
    pub fn begin_attempt(&mut self) -> Result<PinAttempt, u8> {
        self.check_attempt_allowed()?;
        self.persistent.pin_retries -= 1;
        Ok(PinAttempt(()))
    }

    /// Compare `candidate`, the decrypted pinHashEnc (`None` if it failed to
    /// decrypt), against the stored PIN hash in constant time.
    ///
    /// On a match: "The authenticator sets the pinRetries counter to maximum
    /// value."  On an error or mismatch the result is, in order:
    /// `CTAP2_ERR_PIN_BLOCKED` if pinRetries is now 0,
    /// `CTAP2_ERR_PIN_AUTH_BLOCKED` on the third consecutive mismatch, and
    /// `CTAP2_ERR_PIN_INVALID` otherwise.
    pub fn finish_attempt(
        &mut self,
        attempt: PinAttempt,
        candidate: Option<&[u8]>,
    ) -> Result<(), u8> {
        let PinAttempt(()) = attempt;
        let matches = match (self.persistent.pin_hash.as_ref(), candidate) {
            (Some(stored), Some(candidate)) => bool::from(stored.as_slice().ct_eq(candidate)),
            _ => false,
        };
        if matches {
            self.persistent.pin_retries = MAX_PIN_RETRIES;
            self.consecutive_mismatches = 0;
            return Ok(());
        }
        self.consecutive_mismatches = self.consecutive_mismatches.saturating_add(1);
        if self.persistent.pin_retries == 0 {
            Err(CTAP2_ERR_PIN_BLOCKED)
        } else if self.power_cycle_required() {
            Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
        } else {
            Err(CTAP2_ERR_PIN_INVALID)
        }
    }
}

pub(crate) struct PinState {
    pin: PinRetryState,
    pub(crate) pin_uv_auth_token: Option<[u8; 32]>,
    pub(crate) pin_uv_auth_permissions: u8,
    pub(crate) pin_uv_auth_rp_id: Option<String>,
    pub(crate) pin_uv_auth_rp_provided: bool,
}

impl PinState {
    pub(crate) const MIN_PIN_LENGTH: usize = 4;

    pub(crate) fn new() -> Self {
        Self::from_persistent(PersistentPinState::default())
    }

    /// The PIN state at power-up, from its persisted part.
    pub(crate) fn from_persistent(persistent: PersistentPinState) -> Self {
        Self {
            pin: PinRetryState::power_up(persistent),
            pin_uv_auth_token: None,
            pin_uv_auth_permissions: 0,
            pin_uv_auth_rp_id: None,
            pin_uv_auth_rp_provided: false,
        }
    }

    pub(crate) fn persistent(&self) -> &PersistentPinState {
        self.pin.persistent()
    }

    pub(crate) fn is_set(&self) -> bool {
        self.pin.is_set()
    }

    pub(crate) fn set_pin(&mut self, hash: [u8; 16]) {
        self.pin.set_pin(hash);
        self.clear_pin_uv_auth_token();
    }

    pub(crate) fn retries(&self) -> u8 {
        self.pin.retries()
    }

    pub(crate) fn needs_power_cycle(&self) -> bool {
        self.pin.power_cycle_required()
    }

    pub(crate) fn check_pin_attempt_allowed(&self) -> Result<(), u8> {
        self.pin.check_attempt_allowed()
    }

    pub(crate) fn begin_pin_attempt(&mut self) -> Result<PinAttempt, u8> {
        self.pin.begin_attempt()
    }

    pub(crate) fn finish_pin_attempt(
        &mut self,
        attempt: PinAttempt,
        candidate: Option<&[u8]>,
    ) -> Result<(), u8> {
        self.pin.finish_attempt(attempt, candidate)
    }

    fn clear_pin_uv_auth_token(&mut self) {
        if let Some(mut token) = self.pin_uv_auth_token.take() {
            token.zeroize();
        }
        self.pin_uv_auth_permissions = 0;
        self.pin_uv_auth_rp_provided = false;
        if let Some(mut rp_id) = self.pin_uv_auth_rp_id.take() {
            rp_id.zeroize();
        }
    }

    pub(crate) fn set_pin_uv_auth_token(
        &mut self,
        token: [u8; 32],
        permissions: u8,
        rp_id: Option<String>,
    ) {
        self.clear_pin_uv_auth_token();
        self.pin_uv_auth_token = Some(token);
        self.pin_uv_auth_permissions = permissions;
        self.pin_uv_auth_rp_id = rp_id;
        self.pin_uv_auth_rp_provided = self.pin_uv_auth_rp_id.is_some();
    }

    pub(crate) fn pin_uv_auth_token(&self) -> Option<[u8; 32]> {
        self.pin_uv_auth_token.as_ref().map(|token| {
            let mut copy = [0u8; 32];
            copy.copy_from_slice(token);
            copy
        })
    }

    pub(crate) fn has_permission(&self, permission: u8) -> bool {
        (self.pin_uv_auth_permissions & permission) != 0
    }

    pub(crate) fn permissions_rp_id(&self) -> Option<&str> {
        self.pin_uv_auth_rp_id.as_deref()
    }

    pub(super) fn should_bind_pin_token_to_rp(&self) -> bool {
        self.pin_uv_auth_rp_provided
    }

    pub(super) fn set_permissions_rp_id(&mut self, rp_id: &str) {
        if !self.should_bind_pin_token_to_rp() {
            return;
        }
        if let Some(mut existing) = self.pin_uv_auth_rp_id.take() {
            existing.zeroize();
        }
        self.pin_uv_auth_rp_id = Some(rp_id.to_string());
    }
}

impl Drop for PinState {
    fn drop(&mut self) {
        self.clear_pin_uv_auth_token();
    }
}
