//! The `pqkey` binary on the default state directory, with a fake
//! `systemctl` in the place of the user manager: `pqkey status` names a
//! service that systemd gave up restarting, where the cause is logged and
//! the fix, after one `systemctl show`, and exits with status 0 even when its
//! reader goes away; `pqkey start` resets the failed state before it starts
//! the service, which systemd refuses for a while once it has given up, and
//! starts a service whose reset fails, as where systemd has unloaded it.
#![cfg(target_os = "linux")]

use std::{
    env, fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};

use pqkey::state_lock::{self, StateLock};

/// A user manager with one unit, pqkey.service, whose properties are the
/// lines of the file `$UNIT`, as systemd 249, 252 and 255 behave: `show`
/// prints the properties asked for, in the file's order; `reset-failed`
/// fails for an inactive unit that is not enabled, which systemd unloads
/// after `show` loaded it, and otherwise resets a failed one; `start`
/// refuses a failed one, as systemd does for a while once it has given up
/// restarting it. Every call goes to `$TRACE`. While `$HOLD` names a file
/// that does not exist yet, `show` waits for it, unless the test's files are
/// gone.
const SYSTEMCTL: &str = r#"#!/bin/sh
PATH=/usr/bin:/bin
printf '%s\n' "$*" >> "$TRACE"
case "$2" in
show)
    while [ -n "${HOLD-}" ] && [ ! -e "$HOLD" ] && [ -e "$UNIT" ]; do sleep 0.01; done
    if [ "$5" = --value ]; then
        sed -n "s/^$4=//p" "$UNIT"
    else
        grep -E "^($(printf %s "$4" | tr , '|'))=" "$UNIT"
    fi
    ;;
reset-failed)
    if grep -qx UnitFileState=disabled "$UNIT" && grep -qx ActiveState=inactive "$UNIT"; then
        echo "Failed to reset failed state of unit $3: Unit $3 not loaded." >&2
        exit 1
    fi
    sed -i 's/^ActiveState=failed$/ActiveState=inactive/; s/^SubState=failed$/SubState=dead/; s/^Result=.*/Result=success/' "$UNIT"
    ;;
start)
    if grep -qx ActiveState=failed "$UNIT"; then
        echo "Job for $3 failed because the control process exited with error code." >&2
        exit 1
    fi
    ;;
*)
    exit 1
    ;;
esac
"#;

/// The unit once systemd has given up restarting a key that failed five
/// times within a minute (`StartLimitBurst=` of the shipped unit), as
/// systemd 252 shows it.
const GAVE_UP: &str = "Result=exit-code\nExecMainStatus=1\nLoadState=loaded\nActiveState=failed\n\
                       SubState=failed\nUnitFileState=enabled\n";
/// The unit after `systemctl --user disable pqkey`, with the key stopped.
const DISABLED: &str = "Result=success\nExecMainStatus=0\nLoadState=loaded\nActiveState=inactive\n\
                        SubState=dead\nUnitFileState=disabled\n";

/// What `pqkey status` says about [`GAVE_UP`].
const GAVE_UP_PROBLEM: &str = "\n  ! the systemd user service pqkey.service failed: the key exited \
    with status 1\n    Fix: see why in `journalctl --user -u pqkey`, fix that, then run `pqkey \
    start`\n";
/// The one call with which `pqkey status` asks about the unit.
const STATUS_CALL: &str = "--user show --property \
    LoadState,UnitFileState,ActiveState,SubState,Result,ExecMainStatus pqkey.service";
/// The calls with which `pqkey start` starts the service.
const START_CALLS: [&str; 3] = [
    "--user show --property LoadState --value pqkey.service",
    "--user reset-failed pqkey.service",
    "--user start pqkey.service",
];

/// A home of the test's own: the fake systemctl in `bin`, the unit's
/// properties in `unit`, the calls in `trace`, and the key's default state
/// directory in `data/pqkey`, where no key runs.
struct Home(PathBuf);

impl Home {
    fn new(name: &str, unit: &str) -> Self {
        let dir = env::temp_dir().join(format!(
            "pqkey-failed-service-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        let systemctl = dir.join("bin").join("systemctl");
        fs::write(&systemctl, SYSTEMCTL).unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(dir.join("unit"), unit).unwrap();
        let home = Self(dir);
        pqkey::state::ensure_state_dir(&home.state_dir()).unwrap();
        home
    }

    fn state_dir(&self) -> PathBuf {
        self.0.join("data").join("pqkey")
    }

    /// `pqkey ARGS` on the default state directory here.
    fn pqkey(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pqkey"));
        command
            .args(args)
            .env_remove("PQKEY_STATE_DIR")
            .env("PATH", self.0.join("bin"))
            .env("XDG_DATA_HOME", self.0.join("data"))
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            // No session bus there.
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", self.0.join("no-bus").display()),
            )
            .env("UNIT", self.0.join("unit"))
            .env("TRACE", self.0.join("trace"))
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        command
    }

    /// The systemctl calls made since the last look.
    fn calls(&self) -> Vec<String> {
        let trace = self.0.join("trace");
        let calls = fs::read_to_string(&trace)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        let _ = fs::remove_file(&trace);
        calls
    }

    /// Run `pqkey start`, and play the key that the service starts: once
    /// systemctl has been asked to start it, this process takes the state
    /// lock and publishes its pid, as the key does once it serves, until
    /// `pqkey start` has ended.
    fn start(&self) -> Output {
        let mut start = self
            .pqkey(&["start"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let trace = self.0.join("trace");
        let mut key = None;
        while start.try_wait().unwrap().is_none() {
            if key.is_none()
                && fs::read_to_string(&trace)
                    .unwrap_or_default()
                    .lines()
                    .any(|call| call == "--user start pqkey.service")
            {
                let lock = StateLock::try_acquire(&self.state_dir()).unwrap().unwrap();
                state_lock::write_pid_file(&self.state_dir(), &lock).unwrap();
                key = Some(lock);
            }
            thread::sleep(Duration::from_millis(10));
        }
        start.wait_with_output().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// `pqkey status` names a service that systemd gave up restarting, where
/// the cause is logged and the fix, after one `systemctl show`.
#[test]
fn status_names_a_service_that_systemd_gave_up_on() {
    let home = Home::new("status", GAVE_UP);
    let status = home.pqkey(&["status"]).output().unwrap();
    assert_eq!(status.status.code(), Some(0), "{status:?}");
    let out = text(&status.stdout);
    assert!(
        out.starts_with("Key:      not running; `pqkey start` starts it\n"),
        "{out}"
    );
    assert!(out.contains(GAVE_UP_PROBLEM), "{out}");
    assert_eq!(home.calls(), [STATUS_CALL]);
}

/// `pqkey status` still exits with status 0, and says nothing, when its
/// reader goes away after the first line, as `pqkey status | head -1` does,
/// before the problems are written.
#[test]
fn status_ends_quietly_when_its_reader_goes() {
    let home = Home::new("closed", GAVE_UP);
    let hold = home.0.join("hold");
    let (mut reader, writer) = std::io::pipe().unwrap();
    let status = home
        .pqkey(&["status"])
        .env("HOLD", &hold)
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = Vec::new();
    while !first.ends_with(b"\n") {
        let mut byte = [0];
        assert_eq!(
            reader.read(&mut byte).unwrap(),
            1,
            "status ended before its first line"
        );
        first.push(byte[0]);
    }
    assert_eq!(
        text(&first),
        "Key:      not running; `pqkey start` starts it\n"
    );
    drop(reader);
    fs::write(&hold, "").unwrap();
    let status = status.wait_with_output().unwrap();
    assert_eq!(status.status.code(), Some(0), "{status:?}");
    assert_eq!(text(&status.stderr), "");
    assert_eq!(home.calls(), [STATUS_CALL]);
}

/// `pqkey start` resets the failed state of a service that systemd gave up
/// restarting, which it would refuse to start for a while otherwise, then
/// starts it and waits for the key.
#[test]
fn start_resets_the_failed_state_before_it_starts_the_service() {
    let home = Home::new("start", GAVE_UP);
    let started = home.start();
    assert_eq!(started.status.code(), Some(0), "{started:?}");
    assert_eq!(
        text(&started.stdout),
        format!(
            "Key started (pid {}, systemd user service pqkey.service)\n",
            std::process::id()
        )
    );
    assert_eq!(text(&started.stderr), "");
    assert_eq!(home.calls(), START_CALLS);
}

/// Where systemd has unloaded the service, as it does one that is inactive
/// and not enabled, resetting its failed state fails; `pqkey start` starts
/// it all the same.
#[test]
fn start_starts_a_service_whose_reset_fails() {
    let home = Home::new("unloaded", DISABLED);
    let started = home.start();
    assert_eq!(started.status.code(), Some(0), "{started:?}");
    assert_eq!(
        text(&started.stdout),
        format!(
            "Key started (pid {}, systemd user service pqkey.service)\n",
            std::process::id()
        )
    );
    assert_eq!(text(&started.stderr), "");
    assert_eq!(home.calls(), START_CALLS);
}
