//! Non-secret options and executable identity of the daemon holding the lock.

use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

use nix::unistd::Pid;

use super::{DaemonArgs, daemon_args_from};
use crate::state_lock::{self, DaemonState, StateLock};

const VERSION: &str = "pqkey-daemon-v1";

pub(crate) struct DaemonInfo {
    pid: Pid,
    device: u64,
    inode: u64,
    cmdline: Vec<u8>,
}

impl DaemonInfo {
    pub fn current(args: &DaemonArgs) -> io::Result<Self> {
        let (device, inode) = crate::platform::current_executable_identity()?;
        Ok(Self::from_identity(args, (device, inode)))
    }

    pub(crate) fn from_identity(args: &DaemonArgs, (device, inode): (u64, u64)) -> Self {
        let mut cmdline = b"pqkey\0run\0".to_vec();
        for arg in args.to_args() {
            cmdline.extend_from_slice(arg.as_encoded_bytes());
            cmdline.push(0);
        }
        Self {
            pid: Pid::this(),
            device,
            inode,
            cmdline,
        }
    }

    pub fn publish(&self, state_dir: &Path, lock: &StateLock) -> io::Result<()> {
        let mut bytes =
            format!("{VERSION} {} {} {}\n", self.pid, self.device, self.inode).into_bytes();
        bytes.extend_from_slice(&self.cmdline);
        state_lock::write_info_file(state_dir, lock, &bytes)
    }

    pub fn read(state_dir: &Path, pid: Pid) -> io::Result<Self> {
        if state_lock::daemon_state(state_dir)? != DaemonState::Running(pid) {
            return Err(invalid_info());
        }
        let bytes = fs::read(state_dir.join(state_lock::INFO_FILE))?;
        let end = bytes
            .iter()
            .position(|&byte| byte == b'\n')
            .ok_or_else(invalid_info)?;
        let header = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid_info())?;
        let mut fields = header.split_ascii_whitespace();
        let (Some(version), Some(recorded), Some(device), Some(inode), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(invalid_info());
        };
        if version != VERSION || recorded.parse::<i32>().ok() != Some(pid.as_raw()) {
            return Err(invalid_info());
        }
        let cmdline = bytes[end + 1..].to_vec();
        if daemon_args_from(&cmdline).is_none() {
            return Err(invalid_info());
        }
        Ok(Self {
            pid,
            device: device.parse().map_err(|_| invalid_info())?,
            inode: inode.parse().map_err(|_| invalid_info())?,
            cmdline,
        })
    }

    pub fn args(&self) -> io::Result<DaemonArgs> {
        daemon_args_from(&self.cmdline).ok_or_else(invalid_info)
    }

    pub fn runs_binary(&self, binary: &Path) -> io::Result<bool> {
        let metadata = fs::metadata(binary)?;
        Ok(self.device == metadata.dev() && self.inode == metadata.ino())
    }
}

fn invalid_info() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the daemon information is stale or invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::os::unix::fs::PermissionsExt;

    fn publish(dir: &TempDir, args: &DaemonArgs) -> StateLock {
        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        crate::test_support::daemon_info(args)
            .publish(dir.path(), &lock)
            .unwrap();
        state_lock::write_pid_file(dir.path(), &lock).unwrap();
        lock
    }

    #[test]
    fn information_preserves_options_and_is_private() {
        let dir = TempDir::new("daemon-info-options");
        let args = DaemonArgs {
            name: "a key with spaces\nand a newline".into(),
            presence: super::super::PresenceArg::Unanswered,
            product_id: 5,
            ..DaemonArgs::default()
        };
        let _lock = publish(&dir, &args);
        let info = DaemonInfo::read(dir.path(), Pid::this()).unwrap();
        assert_eq!(info.args().unwrap().to_args(), args.to_args());
        assert_eq!(
            super::super::daemon_args_of(dir.path(), Pid::this())
                .unwrap()
                .to_args(),
            args.to_args()
        );
        let metadata = fs::metadata(dir.path().join(state_lock::INFO_FILE)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(info.runs_binary(&std::env::current_exe().unwrap()).unwrap());
    }

    #[test]
    fn only_the_locked_ready_pid_can_use_the_information() {
        let dir = TempDir::new("daemon-info-lifecycle");
        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        let info = crate::test_support::daemon_info(&DaemonArgs::default());
        info.publish(dir.path(), &lock).unwrap();
        assert!(DaemonInfo::read(dir.path(), Pid::this()).is_err());
        state_lock::write_pid_file(dir.path(), &lock).unwrap();
        assert!(DaemonInfo::read(dir.path(), Pid::this()).is_ok());
        assert!(DaemonInfo::read(dir.path(), Pid::from_raw(Pid::this().as_raw() + 1)).is_err());
        drop(lock);
        assert!(DaemonInfo::read(dir.path(), Pid::this()).is_err());
        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        state_lock::remove_pid_file(dir.path(), &lock).unwrap();
        assert!(DaemonInfo::read(dir.path(), Pid::this()).is_err());
        state_lock::remove_info_file(dir.path(), &lock).unwrap();
        assert!(!dir.path().join(state_lock::INFO_FILE).exists());
    }

    #[test]
    fn malformed_or_stale_information_is_rejected() {
        let dir = TempDir::new("daemon-info-invalid");
        let _lock = publish(&dir, &DaemonArgs::default());
        for bytes in [
            b"".as_slice(),
            b"not a header\npqkey\0run\0",
            b"pqkey-daemon-v1 2 0 0\npqkey\0run\0",
            b"pqkey-daemon-v1 2 0 0 extra\npqkey\0run\0",
        ] {
            fs::write(dir.path().join(state_lock::INFO_FILE), bytes).unwrap();
            assert!(DaemonInfo::read(dir.path(), Pid::this()).is_err());
        }
        let mut info = crate::test_support::daemon_info(&DaemonArgs::default());
        info.cmdline = b"pqkey\0status\0".to_vec();
        info.publish(dir.path(), &_lock).unwrap();
        assert!(DaemonInfo::read(dir.path(), Pid::this()).is_err());
    }

    #[test]
    fn replacing_a_binary_changes_its_identity() {
        let dir = TempDir::new("daemon-info-replacement");
        let binary = dir.path().join("pqkey");
        fs::write(&binary, b"old binary").unwrap();
        let metadata = fs::metadata(&binary).unwrap();
        let mut info = crate::test_support::daemon_info(&DaemonArgs::default());
        info.device = metadata.dev();
        info.inode = metadata.ino();
        assert!(info.runs_binary(&binary).unwrap());
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, b"new binary").unwrap();
        fs::rename(replacement, &binary).unwrap();
        assert!(!info.runs_binary(&binary).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_dumpable_daemon_can_be_inspected() {
        use std::{
            io::{BufRead, Write},
            process::{Command, Stdio},
        };
        const CHILD: &str = "PQKEY_INFO_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let path = std::path::PathBuf::from(path);
            let lock = StateLock::try_acquire(&path).unwrap().unwrap();
            let args = DaemonArgs {
                presence: super::super::PresenceArg::Unanswered,
                product_id: 5,
                name: "a child's key".into(),
                ..DaemonArgs::default()
            };
            DaemonInfo::current(&args)
                .unwrap()
                .publish(&path, &lock)
                .unwrap();
            state_lock::write_pid_file(&path, &lock).unwrap();
            nix::sys::prctl::set_dumpable(false).unwrap();
            assert!(!nix::sys::prctl::get_dumpable().unwrap());
            writeln!(io::stdout(), "ready").unwrap();
            io::stdout().flush().unwrap();
            let _ = io::stdin().read_line(&mut String::new());
            state_lock::remove_pid_file(&path, &lock).unwrap();
            state_lock::remove_info_file(&path, &lock).unwrap();
            return;
        }
        let dir = TempDir::new("daemon-info-child");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::daemon_info::tests::a_non_dumpable_daemon_can_be_inspected",
                "--nocapture",
            ])
            .env(CHILD, dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap() > 0 {
            // libtest can prefix the line with the test's name.
            if line.trim_end().ends_with("ready") {
                break;
            }
            line.clear();
        }
        let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
        let info = DaemonInfo::read(dir.path(), pid);
        let args = super::super::daemon_args_of(dir.path(), pid);
        let denied = fs::read_link(format!("/proc/{pid}/exe")).is_err();
        drop(child.stdin.take());
        let status = child.wait().unwrap();
        assert!(status.success());
        let args = args.unwrap();
        assert_eq!(args.product_id, 5);
        assert_eq!(args.presence, super::super::PresenceArg::Unanswered);
        assert_eq!(args.name, "a child's key");
        assert!(
            info.unwrap()
                .runs_binary(&std::env::current_exe().unwrap())
                .unwrap()
        );
        if !nix::unistd::geteuid().is_root() {
            assert!(denied);
        }
        assert!(!dir.path().join(state_lock::PID_FILE).exists());
        assert!(!dir.path().join(state_lock::INFO_FILE).exists());
    }
}
