//! The `pqkey` binary when its output goes nowhere: a pipe whose reader has
//! exited, as after `pqkey status | head -1`, and a full device.
//! `println!` panicked in both cases (exit status 101).
//! Failed startup must also remove stale runtime information and its pid.

#[cfg(target_os = "linux")]
use std::{
    env, fs, io,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

/// A state directory of the test's own, which no key runs on.
#[cfg(target_os = "linux")]
fn state_dir(name: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("pqkey-cli-output-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// `pqkey ARGS` on `state_dir`, with standard output going to `stdout` and
/// standard error to `stderr`, or captured.
#[cfg(target_os = "linux")]
fn pqkey(args: &[&str], name: &str, stdout: Stdio, stderr: Option<Stdio>) -> Output {
    let dir = state_dir(name);
    let mut command = Command::new(env!("CARGO_BIN_EXE_pqkey"));
    command
        .args(args)
        .arg("--state-dir")
        .arg(&dir)
        .stdin(Stdio::null())
        .stdout(stdout);
    command.stderr(stderr.unwrap_or_else(Stdio::piped));
    let output = command.output().expect("run pqkey");
    let _ = fs::remove_dir_all(&dir);
    output
}

/// The write end of a pipe whose read end is closed.
#[cfg(target_os = "linux")]
fn closed_pipe() -> Stdio {
    let (reader, writer) = io::pipe().expect("pipe");
    drop(reader);
    writer.into()
}

/// /dev/full, where every write fails with ENOSPC. macOS has no such device.
#[cfg(target_os = "linux")]
fn full_device() -> Stdio {
    fs::File::options()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full")
        .into()
}

#[cfg(target_os = "linux")]
#[test]
fn a_closed_standard_output_ends_pqkey_quietly() {
    let output = pqkey(&["status"], "closed", closed_pipe(), None);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[cfg(target_os = "linux")]
#[test]
fn failed_startup_removes_stale_runtime_files() {
    let dir = state_dir("failed-startup");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(pqkey::state_lock::PID_FILE), b"12345\n").unwrap();
    fs::write(dir.join(pqkey::state_lock::INFO_FILE), b"stale information").unwrap();
    // A file where the keys directory belongs forces failure before uhid is
    // opened, on both platforms and even when tests run as root.
    fs::write(dir.join("keys"), b"not a directory").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pqkey"))
        .arg("run")
        .arg("--state-dir")
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!dir.join(pqkey::state_lock::PID_FILE).exists());
    assert!(!dir.join(pqkey::state_lock::INFO_FILE).exists());
    assert_eq!(
        pqkey::state_lock::daemon_state(&dir).unwrap(),
        pqkey::state_lock::DaemonState::Stopped
    );
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn a_failing_standard_output_is_an_error() {
    let output = pqkey(&["status"], "full", full_device(), None);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "pqkey: cannot write to standard output: No space left on device (os error 28)\n"
    );
}

/// An error that cannot be reported still ends pqkey with status 1.
#[cfg(target_os = "linux")]
#[test]
fn a_failing_standard_error_is_no_panic() {
    let output = pqkey(&["pin"], "stderr", Stdio::piped(), Some(full_device()));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        env, fs,
        process::{Command, Stdio},
    };

    #[test]
    fn commands_fail_with_one_error_before_touching_state() {
        let dir = env::temp_dir().join(format!("pqkey-macos-cli-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("authenticator.pid"), b"12345\n").unwrap();
        fs::write(dir.join("authenticator.info"), b"unchanged").unwrap();
        for args in [
            vec![],
            vec!["run"],
            vec!["run", "--presence", "auto-approve"],
            vec!["start"],
            vec!["start", "--presence", "unanswered"],
            vec!["stop"],
            vec!["status"],
            vec!["pin"],
            vec!["passkeys"],
            vec!["passkeys", "delete", "example", "--yes"],
            vec!["reset"],
            vec!["reset", "--yes"],
            vec!["setup"],
            vec!["setup", "--yes"],
            vec!["setup", "--uninstall"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_pqkey"))
                .args(&args)
                .arg("--state-dir")
                .arg(&dir)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
            assert_eq!(
                output.stderr, b"pqkey: the key does not run on macOS yet\n",
                "{args:?}"
            );
            assert_eq!(fs::read(dir.join("authenticator.pid")).unwrap(), b"12345\n");
            assert_eq!(
                fs::read(dir.join("authenticator.info")).unwrap(),
                b"unchanged"
            );
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn help_and_version_succeed_and_parse_errors_keep_their_status() {
        for args in [["--help"], ["--version"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_pqkey"))
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            assert!(!output.stdout.is_empty());
        }
        let output = Command::new(env!("CARGO_BIN_EXE_pqkey"))
            .arg("--unknown")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("does not run on macOS yet"));
    }

    #[test]
    fn unsupported_commands_do_not_create_the_default_state_directory() {
        let home = env::temp_dir().join(format!("pqkey-macos-home-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let output = Command::new(env!("CARGO_BIN_EXE_pqkey"))
            .arg("run")
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("xdg"))
            .env_remove("PQKEY_STATE_DIR")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stderr, b"pqkey: the key does not run on macOS yet\n");
        assert!(!home.exists());
    }
}
