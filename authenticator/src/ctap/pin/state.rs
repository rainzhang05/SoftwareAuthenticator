//! PIN retry counters, the power-cycle lockout and the current pinUvAuthToken.

use zeroize::Zeroize;

use transport_core::ctap::constants::*;

pub(crate) const MAX_PIN_RETRIES: u8 = 8;
pub(crate) const MAX_PIN_FAILURES_BEFORE_BLOCK: u8 = 3;

#[derive(Debug)]
pub(crate) struct PinState {
    pub(crate) pin_hash: Option<[u8; 16]>,
    pub(crate) pin_retries: u8,
    pub(crate) consecutive_failures: u8,
    pub(crate) pin_auth_blocked: bool,
    pub(crate) pin_uv_auth_token: Option<[u8; 32]>,
    pub(crate) pin_uv_auth_permissions: u8,
    pub(crate) pin_uv_auth_rp_id: Option<String>,
    pub(crate) pin_uv_auth_rp_provided: bool,
}

impl PinState {
    pub(crate) const MIN_PIN_LENGTH: usize = 4;

    pub(crate) fn new() -> Self {
        Self {
            pin_hash: None,
            pin_retries: MAX_PIN_RETRIES,
            consecutive_failures: 0,
            pin_auth_blocked: false,
            pin_uv_auth_token: None,
            pin_uv_auth_permissions: 0,
            pin_uv_auth_rp_id: None,
            pin_uv_auth_rp_provided: false,
        }
    }

    pub(crate) fn is_set(&self) -> bool {
        self.pin_hash.is_some()
    }

    pub(crate) fn set_pin(&mut self, hash: [u8; 16]) {
        self.pin_hash = Some(hash);
        self.pin_retries = MAX_PIN_RETRIES;
        self.consecutive_failures = 0;
        self.clear_pin_uv_auth_token();
    }

    pub(crate) fn retries(&self) -> u8 {
        self.pin_retries
    }

    pub(crate) fn needs_power_cycle(&self) -> bool {
        self.pin_auth_blocked
    }

    pub(crate) fn verify_pin_hash(&mut self, candidate: &[u8; 16]) -> Result<(), u8> {
        let Some(stored) = self.pin_hash else {
            return Err(CTAP2_ERR_PIN_NOT_SET);
        };
        if self.pin_auth_blocked {
            return Err(CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        if stored == *candidate {
            self.pin_retries = MAX_PIN_RETRIES;
            self.consecutive_failures = 0;
            Ok(())
        } else {
            if self.pin_retries > 0 {
                self.pin_retries -= 1;
            }
            if self.pin_retries == 0 {
                return Err(CTAP2_ERR_PIN_BLOCKED);
            }
            self.consecutive_failures = self
                .consecutive_failures
                .saturating_add(1)
                .min(MAX_PIN_FAILURES_BEFORE_BLOCK);
            if self.consecutive_failures >= MAX_PIN_FAILURES_BEFORE_BLOCK {
                self.pin_auth_blocked = true;
                Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
            } else {
                Err(CTAP2_ERR_PIN_INVALID)
            }
        }
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
