//! Startup protection tested in a child, without lowering the runner's limits.
#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use std::{fs, process::Command};

use nix::sys::resource::{Resource, getrlimit, setrlimit};
use pqkey::{
    presence::PresenceMode,
    service::{self, AttestationConfig, RunnerConfig},
    shutdown::ShutdownSignal,
    transport::HidDeviceDescriptor,
};

#[test]
fn startup_disables_dumps_before_opening_the_store() {
    const CHILD: &str = "PQKEY_CORE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "startup_disables_dumps_before_opening_the_store",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let (_, hard) = getrlimit(Resource::RLIMIT_CORE).unwrap();
    if hard > 0 {
        setrlimit(Resource::RLIMIT_CORE, hard.min(1024), hard).unwrap();
    }
    #[cfg(target_os = "linux")]
    {
        nix::sys::prctl::set_dumpable(true).unwrap();
        assert!(nix::sys::prctl::get_dumpable().unwrap());
    }
    let path = std::env::temp_dir().join(format!("pqkey-core-test-{}", std::process::id()));
    fs::write(&path, b"not a directory").unwrap();
    let config = RunnerConfig {
        descriptor: HidDeviceDescriptor::default(),
        state_dir: path.clone(),
        aaguid: [0; 16],
        attestation: AttestationConfig::SelfAttestation,
        presence: PresenceMode::AutoApprove,
        presence_timeout: None,
        allow_late_reset: false,
    };
    assert!(service::run(config, ShutdownSignal::new(), || panic!("device created")).is_err());
    assert_eq!(getrlimit(Resource::RLIMIT_CORE).unwrap(), (0, 0));
    #[cfg(target_os = "linux")]
    assert!(!nix::sys::prctl::get_dumpable().unwrap());
    fs::remove_file(path).unwrap();
}
