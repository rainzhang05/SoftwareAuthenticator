//! User presence: waiting for consent, keepalive signalling and cancellation.

use super::CtapApp;
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use trussed::interrupt::InterruptFlag;
use trussed::try_syscall;
use trussed::types::consent;

use crate::ctap::constants::*;

#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
static WAITING_LOG: Mutex<Vec<bool>> = Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn take_waiting_log() -> Vec<bool> {
    WAITING_LOG
        .lock()
        .expect("waiting log mutex poisoned")
        .drain(..)
        .collect()
}

pub(super) fn noop_keepalive(_: bool) {}

fn set_keepalive_waiting(callback: fn(bool), waiting: bool) {
    callback(waiting);

    #[cfg(test)]
    {
        WAITING_LOG
            .lock()
            .expect("waiting log mutex poisoned")
            .push(waiting);
    }
}

struct WaitingState {
    active: bool,
    callback: fn(bool),
}

impl WaitingState {
    fn begin(callback: fn(bool)) -> Self {
        set_keepalive_waiting(callback, true);
        Self {
            active: true,
            callback,
        }
    }

    fn clear(&mut self) {
        if self.active {
            set_keepalive_waiting(self.callback, false);
            self.active = false;
        }
    }
}

impl Drop for WaitingState {
    fn drop(&mut self) {
        self.clear();
    }
}

struct InterruptWorkGuard<'a> {
    flag: &'a InterruptFlag,
}

impl<'a> InterruptWorkGuard<'a> {
    fn begin(flag: &'a InterruptFlag) -> Self {
        flag.set_working();
        Self { flag }
    }
}

impl<'a> Drop for InterruptWorkGuard<'a> {
    fn drop(&mut self) {
        self.flag.set_idle();
    }
}

pub(super) const USER_PRESENCE_POLL_TIMEOUT_MS: u32 = 200;
pub(super) const USER_PRESENCE_MAX_WAIT_MS: u32 = 10_000;

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    pub(super) fn await_user_presence(&mut self) -> Result<bool, u8> {
        let _interrupt_guard = InterruptWorkGuard::begin(self.interrupt_flag);
        let mut waiting = WaitingState::begin(self.keepalive_callback);
        if self.auto_user_presence {
            waiting.clear();
            return Ok(true);
        }
        let mut waited_ms = 0u32;
        loop {
            if self.interrupt_flag.is_interrupted() {
                waiting.clear();
                return Err(CTAP2_ERR_KEEPALIVE_CANCEL);
            }

            let consent = match try_syscall!(self
                .client
                .confirm_user_present(USER_PRESENCE_POLL_TIMEOUT_MS))
            {
                Ok(reply) => reply,
                Err(_) => {
                    waiting.clear();
                    return Err(CTAP2_ERR_PROCESSING);
                }
            };

            match consent.result {
                Ok(()) => {
                    waiting.clear();
                    return Ok(true);
                }
                Err(consent::Error::TimedOut) => {
                    waited_ms = waited_ms.saturating_add(USER_PRESENCE_POLL_TIMEOUT_MS);
                    if waited_ms >= USER_PRESENCE_MAX_WAIT_MS {
                        waiting.clear();
                        return Err(CTAP2_ERR_NOT_ALLOWED);
                    }
                }
                Err(consent::Error::Interrupted) => {
                    waiting.clear();
                    return Err(CTAP2_ERR_KEEPALIVE_CANCEL);
                }
                Err(consent::Error::TimeoutNotImplemented) => {
                    waiting.clear();
                    return Err(CTAP2_ERR_NOT_ALLOWED);
                }
                Err(consent::Error::FailedToInterrupt) => {
                    waiting.clear();
                    return Err(CTAP2_ERR_PROCESSING);
                }
                Err(_) => {
                    waiting.clear();
                    return Err(CTAP2_ERR_NOT_ALLOWED);
                }
            }
        }
    }
}
