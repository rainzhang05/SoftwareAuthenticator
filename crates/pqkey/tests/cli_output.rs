//! The `pqkey` binary when its output goes nowhere: a pipe whose reader has
//! exited, as after `pqkey status | head -1`, and a full device.
//! `println!` panicked in both cases (exit status 101).

use std::{
    env, fs,
    fs::File,
    io,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

/// A state directory of the test's own, which no key runs on.
fn state_dir(name: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("pqkey-cli-output-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// `pqkey ARGS` on `state_dir`, with standard output going to `stdout` and
/// standard error to `stderr`, or captured.
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
fn closed_pipe() -> Stdio {
    let (reader, writer) = io::pipe().expect("pipe");
    drop(reader);
    writer.into()
}

fn full_device() -> Stdio {
    File::options()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full")
        .into()
}

#[test]
fn a_closed_standard_output_ends_pqkey_quietly() {
    let output = pqkey(&["status"], "closed", closed_pipe(), None);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

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
#[test]
fn a_failing_standard_error_is_no_panic() {
    let output = pqkey(&["pin"], "stderr", Stdio::piped(), Some(full_device()));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}
