//! The systemd user service and Linux startup access warnings.
use super::permissions;
use crate::{
    cli::{checks::Problem, output::errln},
    platform::ServiceAction,
};
use nix::unistd::{self, Group, Pid};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
};

const UNIT: &str = "pqkey.service";
/// The systemd user unit this version ships, with `ExecStart` for
/// `/usr/local/bin/pqkey`.
pub(crate) const UNIT_TEMPLATE: &str =
    include_str!("../../../../../contrib/systemd/user/pqkey.service");
/// Units earlier versions shipped, which setup replaces as it does its own:
/// the one from 2026-10-05 until system calls were filtered.
const EARLIER_UNITS: [&str; 1] = [include_str!("earlier-units/2026-10-05.service")];
/// The properties of the unit that [`UserService::problems`] reads.
const UNIT_STATE: &str = "LoadState,UnitFileState,ActiveState,SubState,Result,ExecMainStatus";
/// The fix for a service that failed. Its log says why, and `pqkey start`
/// resets the failed state before it starts the service, which systemd
/// refuses for a while without that once the service has been started too
/// often (`StartLimitBurst=`).
const FAILED_FIX: &str =
    "see why in `journalctl --user -u pqkey`, fix that, then run `pqkey start`";
/// The fix for a service that is not enabled where it is not known whether
/// the user's service manager lingers: with lingering, SECURITY.md advises
/// disabling the service, which `pqkey setup` would enable again.
const NOT_ENABLED_FIX: &str = "run `pqkey setup`; but if lingering is on (`loginctl \
    enable-linger`) and you disabled it as SECURITY.md advises, leave it and use `pqkey start`";
/// The fixes for a masked service. `unmask` removes a mask where setup
/// installs the unit, and setup installs it again, which also overrides a
/// mask elsewhere, and enables it. Where the user's service manager
/// lingers, SECURITY.md advises disabling it then; where that is not known,
/// the fix says so.
const MASKED_FIX: &str = "run `systemctl --user unmask pqkey`, then `pqkey setup`";
const MASKED_LINGERING_FIX: &str = "run `systemctl --user unmask pqkey`, then `pqkey setup`, \
    then `systemctl --user disable pqkey`, as SECURITY.md advises with lingering";
const MASKED_UNKNOWN_FIX: &str = "run `systemctl --user unmask pqkey`, then `pqkey setup`; but \
    if lingering is on (`loginctl enable-linger`), then also `systemctl --user disable pqkey`, \
    as SECURITY.md advises";

/// Where the user's systemd units live.
fn unit_dir() -> PathBuf {
    match env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".config"),
    }
    .join("systemd/user")
}

/// The unit, running `binary`.
pub(crate) fn unit_file(binary: &Path) -> io::Result<String> {
    let path = binary.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not valid UTF-8", binary.display()),
        )
    })?;
    if path
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the unit cannot run {path:?}; install pqkey somewhere else"),
        ));
    }
    // systemd expands % specifiers in ExecStart, and splits it at spaces
    // outside quotes.
    let escaped = path.replace('%', "%%");
    let state = crate::state::default_state_dir();
    let state = state
        .to_str()
        .ok_or_else(|| io::Error::other("state path is not UTF-8"))?;
    if state
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return Err(io::Error::other(
            "unsupported state path for the user service",
        ));
    }
    // Quoting does not inhibit systemd's $ expansion in ExecStart.
    if escaped.contains('$') || state.contains('$') {
        return Err(io::Error::other("service paths must not contain '$'"));
    }
    let state = state.replace('%', "%%");
    let exec = if escaped.contains(' ') {
        format!("ExecStart=\"{escaped}\" --state-dir \"{state}\" run")
    } else {
        format!("ExecStart={escaped} --state-dir \"{state}\" run")
    };
    let mut unit = String::with_capacity(UNIT_TEMPLATE.len() + exec.len());
    for line in UNIT_TEMPLATE.lines() {
        unit.push_str(if line.starts_with("ExecStart=") {
            &exec
        } else {
            line
        });
        unit.push('\n');
    }
    Ok(unit)
}

/// Install the unit for `binary` and have systemd read it, unless it is
/// installed as it is. Returns whether it changed.
fn install_unit(binary: &Path) -> io::Result<bool> {
    let unit = unit_file(binary)?;
    let dir = unit_dir();
    let path = dir.join(UNIT);
    let installed = match fs::read_to_string(&path) {
        Ok(installed) => Some(installed),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    if let Some(installed) = installed {
        if installed == unit {
            // A prior write may have succeeded while daemon-reload failed.
            systemctl(&[
                "link",
                path.to_str()
                    .ok_or_else(|| io::Error::other("unit path is not UTF-8"))?,
            ])?;
            systemctl(&["daemon-reload"])?;
            return Ok(false);
        }
        if !managed_unit(&installed) {
            // Keep custom arguments and policy. Setup verifies the resulting
            // daemon's identity and readiness rather than replacing them.
            systemctl(&[
                "link",
                path.to_str()
                    .ok_or_else(|| io::Error::other("unit path is not UTF-8"))?,
            ])?;
            systemctl(&["daemon-reload"])?;
            return Ok(false);
        }
    }
    fs::create_dir_all(&dir)?;
    let temporary = dir.join(format!(".{UNIT}.{}", std::process::id()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)?
        .write_all(unit.as_bytes())?;
    fs::rename(&temporary, &path)?;
    systemctl(&[
        "link",
        path.to_str()
            .ok_or_else(|| io::Error::other("unit path is not UTF-8"))?,
    ])?;
    drop(systemctl(&["daemon-reload"])?);
    Ok(true)
}

/// Only units matching the shipped template or one an earlier version
/// shipped, with the default state path, are rewritten. User drop-ins remain
/// under systemd's control.
fn managed_unit(unit: &str) -> bool {
    let without_exec = |text: &str| {
        text.lines()
            .filter(|line| !line.starts_with("ExecStart="))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let one_word = |word: &str| {
        if let Some(inner) = word
            .strip_prefix('"')
            .and_then(|word| word.strip_suffix('"'))
        {
            !inner.contains('"')
        } else {
            !word.is_empty() && !word.chars().any(char::is_whitespace)
        }
    };
    let exec = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .and_then(|line| line.strip_suffix(" run"));
    let default_state = crate::state::default_state_dir();
    let default_state = default_state.to_str().map(|path| path.replace('%', "%%"));
    let ordinary_exec = exec.is_some_and(|exec| match exec.split_once(" --state-dir ") {
        Some((binary, state)) => {
            one_word(binary)
                && one_word(state)
                && default_state.as_deref().is_some_and(|default| {
                    state == default
                        || state
                            .strip_prefix('"')
                            .and_then(|state| state.strip_suffix('"'))
                            == Some(default)
                })
        }
        None => one_word(exec),
    });
    let body = without_exec(unit);
    ordinary_exec
        && std::iter::once(UNIT_TEMPLATE)
            .chain(EARLIER_UNITS)
            .any(|template| without_exec(template) == body)
}

/// Run `systemctl --user` with `args`, failing with its message.
pub fn systemctl(args: &[&str]) -> io::Result<String> {
    let output = ProcessCommand::new("systemctl")
        // The user manager is on its standard runtime bus; notifications
        // may use a distinct desktop/test session bus.
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output().map_err(|err| io::Error::new(err.kind(), format!(
            "cannot run systemctl --user: {err}; setup needs a working systemd user manager in your desktop session"
        )))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(io::Error::other(format!(
            "systemctl --user {} failed: {}; check your systemd user session and `journalctl --user -u pqkey`",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Whether systemd-logind keeps the user's service manager running from
/// boot and after logout (`loginctl enable-linger`), as its `Linger`
/// property says. `None` where it cannot say, as for a user it does not
/// know: one who has no session and does not linger.
fn lingering() -> Option<bool> {
    let output = ProcessCommand::new("loginctl")
        .args([
            "show-user",
            &unistd::getuid().to_string(),
            "--property=Linger",
            "--value",
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "yes" if output.status.success() => Some(true),
        "no" if output.status.success() => Some(false),
        _ => None,
    }
}

pub(crate) fn warn_device_access() {
    if unistd::geteuid().is_root() {
        return;
    }
    match permissions::check_uhid_access() {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => warn_group_membership(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            errln!("warning: /dev/uhid is not available; run `pqkey setup`");
        }
        Err(_) => {}
    }
}

fn warn_group_membership() {
    const GROUP_NAME: &str = "plugdev";
    let plugdev_gid = Group::from_name(GROUP_NAME).ok().flatten().map(|g| g.gid);
    let groups = unistd::getgroups().unwrap_or_default();
    let in_group = plugdev_gid.is_some_and(|gid| groups.contains(&gid) || unistd::getegid() == gid);
    if in_group {
        errln!(
            "warning: cannot open /dev/uhid although you are in '{GROUP_NAME}'; run `pqkey setup`"
        );
    } else {
        errln!(
            "warning: cannot open /dev/uhid: you are not in '{GROUP_NAME}' yet, or have not \
             logged in again since you joined it; run `pqkey setup`"
        );
    }
}

/// The user's installed service. Operations retain systemctl's errors.
pub struct UserService;
impl UserService {
    pub const DESCRIPTION: &str = "systemd user service pqkey.service";
    pub const LOG_HINT: &str = "`journalctl --user -u pqkey.service`";
    // Discovery also serves manually started keys on hosts without a user
    // manager. Setup's install/action calls and final service checks retain
    // errors; a failed discovery must not disable the manual CLI workflow.
    pub fn installed() -> io::Result<bool> {
        Ok(
            systemctl(&["show", "--property", "LoadState", "--value", UNIT])
                .is_ok_and(|state| state == "loaded"),
        )
    }
    pub fn main_pid() -> io::Result<Option<Pid>> {
        Ok(
            systemctl(&["show", "--property", "MainPID", "--value", UNIT])
                .ok()
                .and_then(|pid| pid.parse::<i32>().ok())
                .filter(|pid| *pid > 0)
                .map(Pid::from_raw),
        )
    }
    /// Ensure the daemon uses the desktop bus setup checked in this shell.
    pub fn prepare_session() -> io::Result<bool> {
        if let Some(address) = env::var_os("DBUS_SESSION_BUS_ADDRESS") {
            let address = address
                .to_str()
                .ok_or_else(|| io::Error::other("session bus address is not UTF-8"))?;
            let wanted = format!("DBUS_SESSION_BUS_ADDRESS={address}");
            let current = systemctl(&["show-environment"])?;
            if !current.lines().any(|line| line == wanted) {
                systemctl(&["set-environment", &wanted])?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn action(action: ServiceAction) -> io::Result<()> {
        let action = match action {
            ServiceAction::Start => "start",
            ServiceAction::Restart => "restart",
            ServiceAction::Stop => "stop",
            ServiceAction::Enable => "enable",
            ServiceAction::ResetFailed => "reset-failed",
        };
        systemctl(&[action, UNIT]).map(drop)
    }
    pub fn install(binary: &Path) -> io::Result<bool> {
        install_unit(binary)
    }
    pub fn remove() -> io::Result<Option<PathBuf>> {
        let path = unit_dir().join(UNIT);
        if !path.exists() {
            return Ok(None);
        }
        let _ = systemctl(&["disable", UNIT]);
        fs::remove_file(&path)?;
        drop(systemctl(&["daemon-reload"])?);
        Ok(Some(path))
    }
    pub(crate) fn manual_start_problem(pid: Pid) -> io::Result<Problem> {
        Ok(Problem {
            what: format!(
                "the key (pid {pid}) was started by hand, so the systemd user service cannot run it"
            ),
            fix: "run `pqkey stop && pqkey start`".into(),
        })
    }
    /// What keeps the service from starting the key with the session, or
    /// from running it, as `systemctl --user show` reports its unit: not
    /// installed, masked or not enabled, unless the user's service manager
    /// lingers, and, while the key does not run, failed, or failed and about
    /// to be restarted. A key started by hand has
    /// [`Self::manual_start_problem`] instead of the service's failure.
    pub(crate) fn problems(running: bool) -> io::Result<Vec<Problem>> {
        // As for `installed`, a query that fails finds no service.
        let shown = systemctl(&["show", "--property", UNIT_STATE, UNIT]).unwrap_or_default();
        let property = |name: &str| {
            shown
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
                .unwrap_or_default()
        };
        let not_with_session = "so the key does not start with your session";
        match property("LoadState") {
            "loaded" => {}
            // An empty unit file, or a link to /dev/null. Where setup
            // installs the unit, it cannot enable it until `unmask` has
            // removed that file; its own unit there overrides a mask
            // elsewhere.
            "masked" => {
                let fix = match lingering() {
                    Some(false) => MASKED_FIX,
                    Some(true) => MASKED_LINGERING_FIX,
                    None => MASKED_UNKNOWN_FIX,
                };
                return Ok(vec![Problem::new(
                    format!("the {} is masked, {not_with_session}", Self::DESCRIPTION),
                    fix,
                )]);
            }
            _ => {
                return Ok(vec![Problem::new(
                    "the key does not start with your session",
                    "run `pqkey setup`",
                )]);
            }
        }
        let mut problems = Vec::new();
        if matches!(
            property("UnitFileState"),
            "disabled" | "linked" | "linked-runtime"
        ) {
            let not_enabled = format!(
                "the {} is not enabled, {not_with_session}",
                Self::DESCRIPTION
            );
            match lingering() {
                // What SECURITY.md advises where the service manager
                // lingers, so that the key does not start at boot, before
                // its user logs in; `pqkey start` starts it.
                Some(true) => {}
                Some(false) => problems.push(Problem::new(not_enabled, "run `pqkey setup`")),
                None => problems.push(Problem::new(not_enabled, NOT_ENABLED_FIX)),
            }
        }
        if running {
            return Ok(problems);
        }
        let failed = match (property("Result"), property("ExecMainStatus")) {
            ("exit-code", status) => format!("failed: the key exited with status {status}"),
            ("signal" | "core-dump", signal) => {
                format!("failed: the key was killed by signal {signal}")
            }
            (result, _) => format!("failed with result '{result}'"),
        };
        match (property("ActiveState"), property("SubState")) {
            ("failed", _) => problems.push(Problem::new(
                format!("the {} {failed}", Self::DESCRIPTION),
                FAILED_FIX,
            )),
            // Waiting for RestartSec= to pass, or for the restart's job.
            ("activating", state) if state.starts_with("auto-restart") => {
                problems.push(Problem::new(
                    format!(
                        "the {} {failed}; systemd is restarting it",
                        Self::DESCRIPTION
                    ),
                    FAILED_FIX,
                ));
            }
            _ => {}
        }
        Ok(problems)
    }
}

pub(crate) const START_HELP: &str =
    "Plug the key in: start it, through its systemd user service when that is installed";
pub(crate) const RUN_HELP: &str =
    "Run the key in the foreground until it is stopped (for the systemd unit and test rigs)";
pub(crate) const PRESENCE_NOTIFY_HELP: &str = "Ask with a desktop notification that has Approve \
    and Deny buttons. Without a session bus and a notification server that can show buttons, \
    every request is denied";

#[cfg(test)]
mod setup_tests {
    use super::*;
    #[test]
    fn service_install_child() {
        if env::var_os("PQKEY_SERVICE_CHILD").is_none() {
            return;
        }
        let result = (|| {
            if env::var_os("PQKEY_MANUAL_PROBE").is_some() {
                assert!(!UserService::installed()?);
                assert!(UserService::main_pid()?.is_none());
                return Ok(());
            }
            let changed = UserService::install(Path::new("/usr/local/bin/pqkey"))?;
            println!("CHANGED:{changed}");
            UserService::prepare_session()?;
            UserService::action(ServiceAction::Enable)
        })();
        if let Err(err) = &result {
            eprintln!("{err}");
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }

    #[test]
    fn service_install_repairs_reload_and_preserves_custom_configuration() {
        use crate::test_support::TempDir;
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("setup-service-process");
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let script = bin.join("systemctl");
        fs::write(
            &script,
            r#"#!/bin/sh
printf '%s:%s\n' "$*" "${DBUS_SESSION_BUS_ADDRESS-unset}" >> "$COMMAND_TRACE"
if [ "${FAIL_ACTION-}" = "$2" ]; then echo "fixture $2 failed" >&2; exit 17; fi
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let trace = dir.path().join("trace");
        let config = dir.path().join("config");
        let unit = config.join("systemd/user/pqkey.service");
        let child = |failure: &str| {
            ProcessCommand::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::linux::daemon::setup_tests::service_install_child",
                    "--nocapture",
                ])
                .env("PQKEY_SERVICE_CHILD", "1")
                .env("PATH", &bin)
                .env("XDG_CONFIG_HOME", &config)
                .env("XDG_DATA_HOME", dir.path().join("data space%"))
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/fixture/bus")
                .env("COMMAND_TRACE", &trace)
                .env("FAIL_ACTION", failure)
                .output()
                .unwrap()
        };
        let failed = child("daemon-reload");
        assert_eq!(failed.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&failed.stderr).contains("daemon-reload failed"));
        assert!(unit.exists(), "the first write succeeded, reload did not");
        let repaired = child("");
        assert!(repaired.status.success(), "{repaired:?}");
        assert!(String::from_utf8_lossy(&repaired.stdout).contains("CHANGED:false"));
        let commands = fs::read_to_string(&trace).unwrap();
        assert!(commands.contains("--user link"));
        assert!(commands.contains(
            "--user set-environment DBUS_SESSION_BUS_ADDRESS=unix:path=/fixture/bus:unset"
        ));
        assert!(commands.contains("--user enable pqkey.service:unset"));
        let managed = fs::read_to_string(&unit).unwrap();
        // An update replaces the unit an earlier version installed.
        let exec = managed
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .unwrap();
        let [earlier] = EARLIER_UNITS;
        let earlier: String = earlier
            .lines()
            .map(|line| {
                if line.starts_with("ExecStart=") {
                    exec
                } else {
                    line
                }
            })
            .flat_map(|line| [line, "\n"])
            .collect();
        fs::write(&unit, &earlier).unwrap();
        let updated = child("");
        assert!(updated.status.success(), "{updated:?}");
        assert!(String::from_utf8_lossy(&updated.stdout).contains("CHANGED:true"));
        assert_eq!(fs::read_to_string(&unit).unwrap(), managed);
        let custom_state = UNIT_TEMPLATE.replace(
            "ExecStart=/usr/local/bin/pqkey run",
            "ExecStart=/usr/local/bin/pqkey --state-dir \"/retained/custom state\" run",
        );
        fs::write(&unit, &custom_state).unwrap();
        assert!(child("").status.success());
        assert_eq!(fs::read_to_string(&unit).unwrap(), custom_state);
        fs::write(&unit, managed).unwrap();
        let custom = fs::read_to_string(&unit)
            .unwrap()
            .replace(" run\n", " run --presence unanswered\n");
        fs::write(&unit, &custom).unwrap();
        assert!(child("").status.success());
        assert_eq!(fs::read_to_string(&unit).unwrap(), custom);
        for action in ["link", "enable", "set-environment"] {
            assert_eq!(child(action).status.code(), Some(1), "{action}");
            assert_eq!(fs::read_to_string(&unit).unwrap(), custom);
        }
        let probe = ProcessCommand::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::linux::daemon::setup_tests::service_install_child",
                "--nocapture",
            ])
            .env("PQKEY_SERVICE_CHILD", "1")
            .env("PQKEY_MANUAL_PROBE", "1")
            .env("PATH", &bin)
            .env("XDG_DATA_HOME", dir.path().join("manual"))
            .env("COMMAND_TRACE", &trace)
            .env("FAIL_ACTION", "show")
            .output()
            .unwrap();
        assert!(probe.status.success(), "{probe:?}");
    }

    #[test]
    fn custom_units_are_preserved_and_managed_units_are_upgradable() {
        assert!(managed_unit(UNIT_TEMPLATE));
        let old = UNIT_TEMPLATE.replace(
            "ExecStart=/usr/local/bin/pqkey run",
            "ExecStart=/home/a/.cargo/bin/pqkey run",
        );
        assert!(managed_unit(&old));
        assert!(!managed_unit(
            &old.replace("pqkey run", "pqkey run --presence unanswered")
        ));
        assert!(!managed_unit(
            &old.replace("pqkey run", "pqkey --presence unanswered run")
        ));
        assert!(!managed_unit(&format!("{old}\nEnvironment=CUSTOM=yes\n")));
        assert!(!managed_unit(
            &old.replace("Restart=on-failure", "Restart=no")
        ));
        let [earlier] = EARLIER_UNITS;
        assert!(!earlier.contains("\nSystemCallFilter="));
        assert!(managed_unit(earlier));
        assert!(!managed_unit(&format!(
            "{earlier}\nEnvironment=CUSTOM=yes\n"
        )));
    }

    /// Setup replaces an installed unit only if, apart from `ExecStart=`, it
    /// matches the template or an entry of `EARLIER_UNITS` line for line,
    /// comments included; any other it keeps as the user's own. A template
    /// change that does not add the unit it replaces to `EARLIER_UNITS` would
    /// leave every existing installation on that unit without a word, so the
    /// template's bytes are pinned here.
    #[test]
    fn template_changes_add_the_replaced_unit_to_earlier_units() {
        use sha2::{Digest, Sha256};
        let digest: String = Sha256::digest(UNIT_TEMPLATE.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest, "257e51e450c816f5cf72e141987808aa9293ccaf2d6d61727b12ae4b73794bb7",
            "contrib/systemd/user/pqkey.service changed, and setup upgrades only installed units \
             that match it or an entry of EARLIER_UNITS. Copy its previous version to \
             crates/pqkey/src/platform/linux/earlier-units/<date it first shipped>.service, like \
             2026-10-05.service, add that file to EARLIER_UNITS, then replace the SHA-256 in \
             this test with the new one (left)"
        );
    }

    /// The child of the tests of [`UserService::problems`], through the fake
    /// systemctl of [`problems_of`]: it prints what it finds, with the key
    /// running or not as `PQKEY_PROBLEMS_CHILD` says.
    #[test]
    fn service_problems_child() {
        let Some(running) = env::var_os("PQKEY_PROBLEMS_CHILD") else {
            return;
        };
        for problem in UserService::problems(running == "running").unwrap() {
            println!("\nPROBLEM\t{}\t{}", problem.what, problem.fix);
        }
    }

    /// What [`UserService::problems`] finds, with the key `running` or not,
    /// for a unit that `systemctl --user show` reports as `shown`, or with a
    /// query that fails for `None`, and for a user whose `Linger` property
    /// `loginctl show-user` reports as `linger`, or cannot for `None`; with
    /// the calls it made.
    fn problems_with(
        shown: Option<&str>,
        linger: Option<&str>,
        running: bool,
    ) -> (Vec<Problem>, Vec<String>) {
        use crate::test_support::TempDir;
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("service-problems");
        for (name, script) in [
            (
                "systemctl",
                r#"#!/bin/sh
printf 'systemctl %s\n' "$*" >> "$COMMAND_TRACE"
[ -n "${UNIT_SHOWN+set}" ] || { echo "Failed to connect to bus: No medium found" >&2; exit 1; }
printf '%s\n' "$UNIT_SHOWN"
"#,
            ),
            (
                "loginctl",
                r#"#!/bin/sh
printf 'loginctl %s\n' "$*" >> "$COMMAND_TRACE"
[ -n "${LINGER+set}" ] || { echo "Failed to get user: User ID $2 is not logged in or lingering" >&2; exit 1; }
printf '%s\n' "$LINGER"
"#,
            ),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let trace = dir.path().join("trace");
        let mut child = ProcessCommand::new(env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "platform::linux::daemon::setup_tests::service_problems_child",
                "--nocapture",
            ])
            .env(
                "PQKEY_PROBLEMS_CHILD",
                if running { "running" } else { "stopped" },
            )
            .env("PATH", dir.path())
            .env("COMMAND_TRACE", &trace)
            .env_remove("UNIT_SHOWN")
            .env_remove("LINGER");
        if let Some(shown) = shown {
            child.env("UNIT_SHOWN", shown);
        }
        if let Some(linger) = linger {
            child.env("LINGER", linger);
        }
        let output = child.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let problems = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("PROBLEM\t")?.split_once('\t'))
            .map(|(what, fix)| Problem::new(what, fix))
            .collect();
        let calls = fs::read_to_string(&trace)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        (problems, calls)
    }

    /// The query of the unit with which [`UserService::problems`] starts.
    fn show_call() -> String {
        format!("systemctl --user show --property {UNIT_STATE} pqkey.service")
    }

    /// [`problems_with`] for a unit that is enabled, or neither loaded nor
    /// masked, for which only systemctl is asked, once.
    fn problems_of(shown: Option<&str>, running: bool) -> Vec<Problem> {
        let (problems, calls) = problems_with(shown, None, running);
        assert_eq!(calls, [show_call()]);
        problems
    }

    /// [`problems_with`] for a unit that is masked or not enabled, for which
    /// loginctl is asked next whether this user lingers.
    fn problems_lingering(shown: &str, linger: Option<&str>, running: bool) -> Vec<Problem> {
        let (problems, calls) = problems_with(Some(shown), linger, running);
        assert_eq!(
            calls,
            [
                show_call(),
                format!(
                    "loginctl show-user {} --property=Linger --value",
                    unistd::getuid()
                )
            ]
        );
        problems
    }

    /// What `systemctl --user show --property UNIT_STATE pqkey.service`
    /// prints for a unit in this state: systemd 249, 252 and 255 list the
    /// properties in this order.
    fn shown(
        load: &str,
        file: &str,
        active: &str,
        sub: &str,
        result: &str,
        status: &str,
    ) -> String {
        format!(
            "Result={result}\nExecMainStatus={status}\nLoadState={load}\nActiveState={active}\n\
             SubState={sub}\nUnitFileState={file}"
        )
    }

    /// A unit that failed is named with how, where the cause is logged and
    /// `pqkey start`, which resets the failed state, for every result: a key
    /// that exited, as when systemd gave up restarting it after five starts
    /// within a minute (`Result=exit-code`, not `start-limit-hit`, as systemd
    /// 249 to 255 report it) or after status 3, on which it does not restart
    /// it; a key that was killed; a start that systemd refused
    /// (`start-limit-hit`); and any other. While a key runs, which here can
    /// only be one started by hand, its own problem says what to do instead.
    #[test]
    fn status_names_a_failed_service_with_its_log_and_pqkey_start() {
        for (result, status, failed) in [
            ("exit-code", "1", "failed: the key exited with status 1"),
            ("exit-code", "3", "failed: the key exited with status 3"),
            ("signal", "9", "failed: the key was killed by signal 9"),
            ("core-dump", "11", "failed: the key was killed by signal 11"),
            (
                "start-limit-hit",
                "15",
                "failed with result 'start-limit-hit'",
            ),
            ("timeout", "0", "failed with result 'timeout'"),
        ] {
            let unit = shown("loaded", "enabled", "failed", "failed", result, status);
            assert_eq!(
                problems_of(Some(&unit), false),
                [Problem::new(
                    format!("the systemd user service pqkey.service {failed}"),
                    "see why in `journalctl --user -u pqkey`, fix that, then run `pqkey start`",
                )],
                "{result}"
            );
            let running = problems_of(Some(&unit), true);
            assert!(running.is_empty(), "{result}: {running:?}");
        }
    }

    /// A unit that failed and that systemd is about to restart, waiting out
    /// `RestartSec=` (`auto-restart`) or with the restart queued
    /// (`auto-restart-queued`, systemd 254 and later), is named with how it
    /// failed, its log and `pqkey start`. One that is starting is not.
    #[test]
    fn status_names_a_service_that_systemd_restarts_after_a_failure() {
        for (sub, result, status, failed) in [
            (
                "auto-restart",
                "exit-code",
                "1",
                "failed: the key exited with status 1",
            ),
            (
                "auto-restart-queued",
                "signal",
                "9",
                "failed: the key was killed by signal 9",
            ),
        ] {
            let unit = shown("loaded", "enabled", "activating", sub, result, status);
            assert_eq!(
                problems_of(Some(&unit), false),
                [Problem::new(
                    format!(
                        "the systemd user service pqkey.service {failed}; systemd is restarting it"
                    ),
                    FAILED_FIX,
                )],
                "{sub}"
            );
            let running = problems_of(Some(&unit), true);
            assert!(running.is_empty(), "{sub}: {running:?}");
        }
        let starting = shown("loaded", "enabled", "activating", "start", "success", "0");
        let found = problems_of(Some(&starting), false);
        assert!(found.is_empty(), "{found:?}");
    }

    /// A unit that is not enabled, after `systemctl --user disable pqkey`, or
    /// linked from outside systemd's directories but not enabled, does not
    /// start with the session. Where the user's service manager lingers,
    /// SECURITY.md advises exactly that, so it is not named. Otherwise it is,
    /// whether the key runs or not, and beside a failure: with `pqkey setup`,
    /// which enables it, where the user does not linger, and with that
    /// advice as the exception where loginctl cannot tell, as for a user
    /// without a session. An enabled unit is not named, and loginctl is not
    /// asked.
    #[test]
    fn status_names_a_service_that_is_not_enabled_unless_the_user_lingers() {
        let what = "the systemd user service pqkey.service is not enabled, so the key does not \
                    start with your session";
        let not_lingering = Problem::new(what, "run `pqkey setup`");
        let unknown = Problem::new(
            what,
            "run `pqkey setup`; but if lingering is on (`loginctl enable-linger`) and you \
             disabled it as SECURITY.md advises, leave it and use `pqkey start`",
        );
        for file in ["disabled", "linked", "linked-runtime"] {
            let unit = shown("loaded", file, "inactive", "dead", "success", "0");
            for running in [false, true] {
                assert_eq!(
                    problems_lingering(&unit, Some("no"), running),
                    std::slice::from_ref(&not_lingering),
                    "{file}"
                );
                let lingers = problems_lingering(&unit, Some("yes"), running);
                assert!(lingers.is_empty(), "{file}: {lingers:?}");
                // loginctl fails, or answers something else.
                for linger in [None, Some("")] {
                    assert_eq!(
                        problems_lingering(&unit, linger, running),
                        std::slice::from_ref(&unknown),
                        "{file} {linger:?}"
                    );
                }
            }
        }
        let failed = shown("loaded", "disabled", "failed", "failed", "exit-code", "1");
        let failure = Problem::new(
            "the systemd user service pqkey.service failed: the key exited with status 1",
            FAILED_FIX,
        );
        assert_eq!(
            problems_lingering(&failed, Some("no"), false),
            [not_lingering, failure.clone()]
        );
        assert_eq!(problems_lingering(&failed, Some("yes"), false), [failure]);
        for (running, active, sub) in [(false, "inactive", "dead"), (true, "active", "running")] {
            let enabled = shown("loaded", "enabled", active, sub, "success", "0");
            let found = problems_of(Some(&enabled), running);
            assert!(found.is_empty(), "{found:?}");
        }
    }

    /// A masked unit, an empty unit file or a link to /dev/null, whether in
    /// the user's configuration or in /run (`masked-runtime`), is named
    /// whether the key runs, as a key started by hand can, or not, with
    /// `systemctl --user unmask pqkey`, then `pqkey setup`, which installs
    /// the unit again and enables it. Where the user's service manager
    /// lingers, the fix goes on to disable it, as SECURITY.md advises; where
    /// loginctl cannot tell, it names that as the exception.
    #[test]
    fn status_names_a_masked_service_with_unmask_and_setup() {
        let unmask_and_setup = "run `systemctl --user unmask pqkey`, then `pqkey setup`";
        for (linger, fix) in [
            (Some("no"), unmask_and_setup.to_owned()),
            (
                Some("yes"),
                format!(
                    "{unmask_and_setup}, then `systemctl --user disable pqkey`, as SECURITY.md \
                     advises with lingering"
                ),
            ),
            (
                None,
                format!(
                    "{unmask_and_setup}; but if lingering is on (`loginctl enable-linger`), then \
                     also `systemctl --user disable pqkey`, as SECURITY.md advises"
                ),
            ),
        ] {
            for file in ["masked", "masked-runtime"] {
                let unit = shown("masked", file, "inactive", "dead", "success", "0");
                for running in [false, true] {
                    assert_eq!(
                        problems_lingering(&unit, linger, running),
                        [Problem::new(
                            "the systemd user service pqkey.service is masked, so the key does \
                             not start with your session",
                            fix.as_str(),
                        )],
                        "{file} {linger:?}"
                    );
                }
            }
        }
    }

    /// A unit that is not installed, or that systemd cannot load, and a
    /// user manager that cannot be asked, leave the key without its service,
    /// which `pqkey setup` installs.
    #[test]
    fn status_names_a_missing_service_with_setup() {
        let missing = [Problem::new(
            "the key does not start with your session",
            "run `pqkey setup`",
        )];
        for load in ["not-found", "bad-setting"] {
            let unit = shown(load, "", "inactive", "dead", "success", "0");
            assert_eq!(problems_of(Some(&unit), false), missing, "{load}");
        }
        for running in [false, true] {
            assert_eq!(problems_of(None, running), missing);
        }
    }
}
