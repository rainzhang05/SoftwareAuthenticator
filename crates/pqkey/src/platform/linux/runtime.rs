//! Process protections and the running executable.

use std::{fs, io, os::unix::fs::MetadataExt};

pub(crate) fn current_executable_identity() -> io::Result<(u64, u64)> {
    // Self access is allowed even when this process is non-dumpable, and
    // names the actual inode even if installation replaced its pathname.
    #[cfg(target_os = "linux")]
    let metadata = fs::metadata("/proc/self/exe")?;
    #[cfg(not(target_os = "linux"))]
    let metadata = fs::metadata(std::env::current_exe()?)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Apply before any secrets are read or a device is created. Attempt both
/// protections independently: failure is warned about, never fatal.
pub(crate) fn disable_core_dumps() {
    use nix::sys::resource::{Resource, setrlimit};
    warn_if_protection_failed("disable core files", setrlimit(Resource::RLIMIT_CORE, 0, 0));
    #[cfg(target_os = "linux")]
    warn_if_protection_failed(
        "make the daemon non-dumpable",
        nix::sys::prctl::set_dumpable(false),
    );
}

fn warn_if_protection_failed(setting: &str, result: nix::Result<()>) {
    if let Err(err) = result {
        log::warn!("could not {setting}: {err}");
    }
}

#[cfg(test)]
mod protection_tests {
    use super::*;

    #[test]
    fn failed_protections_warn_and_do_not_stop_startup() {
        use crate::test_support::logs;
        logs::install();
        let first = "apply the test core limit";
        let second = "apply the test dumpability setting";
        warn_if_protection_failed(first, Err(nix::errno::Errno::EPERM));
        warn_if_protection_failed(second, Err(nix::errno::Errno::EINVAL));
        for name in [first, second] {
            let messages = logs::containing(name);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].0, log::Level::Warn);
        }
        warn_if_protection_failed("successful test protection", Ok(()));
        assert!(logs::containing("successful test protection").is_empty());
    }
}
