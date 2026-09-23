//! The clock the CTAP engine's timers run on.

use std::{io, time::Duration};

use nix::time::{ClockId, clock_gettime};
use pqkey_ctap::ctap::Clock;

/// Linux's CLOCK_BOOTTIME, counted from when this clock was created.
///
/// Unlike the monotonic clock behind `std::time::Instant`, it keeps counting
/// while the system is suspended. A pinUvAuthToken therefore expires after
/// the same real time however long the machine slept in between, much as it
/// would on a security key that lost power.
pub(crate) struct BootTimeClock {
    origin: Duration,
}

impl BootTimeClock {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            origin: boot_time()?,
        })
    }
}

impl Clock for BootTimeClock {
    fn now(&self) -> Duration {
        // clock_gettime only fails for a clock the kernel lacks, and `new` has
        // shown this one is there.
        let now = boot_time().expect("CLOCK_BOOTTIME has stopped working");
        now.saturating_sub(self.origin)
    }
}

fn boot_time() -> io::Result<Duration> {
    Ok(clock_gettime(ClockId::CLOCK_BOOTTIME)?.into())
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn counts_from_its_creation_and_never_goes_backwards() {
        let clock = BootTimeClock::new().unwrap();
        let first = clock.now();
        assert!(first < Duration::from_secs(5), "{first:?}");
        thread::sleep(Duration::from_millis(20));
        let second = clock.now();
        assert!(
            second >= first + Duration::from_millis(20),
            "{first:?} then {second:?}"
        );
    }
}
