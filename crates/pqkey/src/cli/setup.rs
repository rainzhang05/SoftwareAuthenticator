//! `pqkey setup [--uninstall]`: install the key for this user, once.
//!
//! The user's part (the systemd user unit, starting the key, a PIN) is done
//! here. What needs root (the udev rules, loading uhid at boot, the group
//! that may open `/dev/uhid`) is written to a short script, summarised a line
//! a step, and run with `sudo sh` once the user agrees: pqkey itself never
//! runs as root.

use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use nix::unistd;

use super::checks::{
    self, MODULES_LOAD_PATH, Membership, Rules, System, UDEV_RULES, UDEV_RULES_PATH, UHID_GROUP,
};
use super::daemon::{self, Running, UNIT};
use super::key;
use super::output::{self, outln};
use crate::state::default_state_dir;

/// The systemd user unit this version ships, with `ExecStart` for
/// `/usr/local/bin/pqkey`.
const UNIT_TEMPLATE: &str = include_str!("../../../../contrib/systemd/user/pqkey.service");

/// Where the user's systemd units live.
fn unit_dir() -> PathBuf {
    match env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".config"),
    }
    .join("systemd/user")
}

/// The unit, running `binary`.
fn unit_file(binary: &Path) -> io::Result<String> {
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
    let exec = if escaped.contains(' ') {
        format!("ExecStart=\"{escaped}\" run")
    } else {
        format!("ExecStart={escaped} run")
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

/// `text` as one shell word.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The steps of setup that need root.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RootSteps {
    /// The shell script that takes them.
    script: String,
    /// What they set up, a line each, to show the user.
    summary: Vec<String>,
}

/// The steps that need root, or `None` if none are left.
fn root_script(system: &System, membership: &Membership) -> Option<RootSteps> {
    let mut steps = Vec::new();
    let mut summary = Vec::new();
    if system.rules() != Rules::Current {
        summary.push("udev rules for /dev/uhid and the key's device".to_owned());
        steps.push(format!(
            "# The udev rules: /dev/uhid for the {UHID_GROUP} group, and the key's device for\n\
             # the active session's user and the Firefox and Chromium snaps.\n\
             cat > {UDEV_RULES_PATH} <<'PQKEY_UDEV_RULES'\n\
             {UDEV_RULES}PQKEY_UDEV_RULES\n\
             chmod 644 {UDEV_RULES_PATH}\n\
             udevadm control --reload-rules"
        ));
    }
    let (at_boot, loaded) = (system.uhid_at_boot(), system.uhid_loaded());
    if !at_boot {
        steps.push(format!(
            "# Load the uhid module at every boot.\necho uhid > {MODULES_LOAD_PATH}"
        ));
    }
    if !loaded {
        steps.push("# Load it now.\nmodprobe uhid".into());
    }
    summary.extend(
        match (at_boot, loaded) {
            (false, false) => Some("uhid module, loaded now and at every boot"),
            (false, true) => Some("uhid module, loaded at every boot"),
            (true, false) => Some("uhid module, loaded now"),
            (true, true) => None,
        }
        .map(str::to_owned),
    );
    if !membership.member {
        summary.push(format!(
            "'{UHID_GROUP}' group for {}, which may open /dev/uhid",
            membership.user
        ));
        let mut step = format!("# Let {} open /dev/uhid.\n", membership.user);
        if !membership.group_exists {
            step.push_str(&format!("groupadd --system {UHID_GROUP}\n"));
        }
        step.push_str(&format!(
            "usermod -aG {UHID_GROUP} {}",
            shell_quote(&membership.user)
        ));
        steps.push(step);
    }
    if steps.is_empty() {
        return None;
    }
    steps.push(
        "# Apply the rules to /dev/uhid and to the key's device, if it runs.\n\
         udevadm trigger --action=change --subsystem-match=misc --sysname-match=uhid\n\
         udevadm trigger --action=change --subsystem-match=hidraw\n\
         udevadm settle"
            .into(),
    );
    if !membership.member {
        // The group applies from the next login on; until then an ACL lets
        // this user, and so the user service, open /dev/uhid right away.
        steps.push(format!(
            "# Until the group applies, at the next login, let the user open /dev/uhid.\n\
             if command -v setfacl >/dev/null; then setfacl -m u:{user}:rw /dev/uhid; fi",
            user = shell_quote(&membership.user)
        ));
    }
    Some(RootSteps {
        script: format!(
            "#!/bin/sh\n# The steps of `pqkey setup` that need root.\nset -eu\n\n{}\n",
            steps.join("\n\n")
        ),
        summary,
    })
}

/// Where install.sh installs pqkey, on every shell's PATH.
const INSTALLED_BINARY: &str = "/usr/local/bin/pqkey";

/// The steps that undo [`root_script`]'s, except the group membership, and
/// remove `binary` if install.sh installed it.
fn root_undo_script(binary: &Path) -> String {
    let mut script = format!(
        "#!/bin/sh\n# Undoes the steps of `pqkey setup` that needed root.\nset -eu\n\n\
         rm -f {UDEV_RULES_PATH} {MODULES_LOAD_PATH}\nudevadm control --reload-rules\n"
    );
    if binary == Path::new(INSTALLED_BINARY) {
        script.push_str(&format!("rm -f {INSTALLED_BINARY}\n"));
    }
    script
}

/// Where the scripts for root go: the user's runtime directory, which only
/// the user (and root) can read.
fn runtime_dir() -> PathBuf {
    env::var_os("XDG_RUNTIME_DIR")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
}

/// Write `script` to `dir`/`name`, readable by this user only.
fn hand_over(dir: &Path, script: &str, name: &str) -> io::Result<PathBuf> {
    let path = dir.join(name);
    match fs::remove_file(&path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    // create_new: never write through a link someone else placed there.
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?
        .write_all(script.as_bytes())?;
    Ok(path)
}

/// Refuse what setup does not do: run as root, or for another state
/// directory than the one the systemd unit uses.
fn check_caller(state_dir: &Path) -> io::Result<()> {
    if unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run `pqkey setup` as the user who uses the key, not as root; it asks for sudo \
             when it needs root",
        ));
    }
    if state_dir != default_state_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pqkey setup only sets up the key in the default state directory",
        ));
    }
    Ok(())
}

/// `pqkey setup`; `yes` runs the steps that need root without asking.
pub fn setup(state_dir: &Path, yes: bool) -> io::Result<()> {
    check_caller(state_dir)?;
    let binary = env::current_exe()?.canonicalize()?;
    if binary.components().any(|part| part.as_os_str() == "target") {
        output::problem(
            format!(
                "{} is in a build directory, which `cargo clean` empties",
                binary.display()
            ),
            "install pqkey with ./install.sh, which runs setup itself",
        )?;
    }
    let system = System::real();
    let membership = checks::membership();

    let interactive = io::stdin().is_terminal();
    if let Some(root) = root_script(&system, &membership) {
        let path = hand_over(&runtime_dir(), &root.script, "pqkey-setup.sh")?;
        if !yes {
            outln!("Setup needs root (sudo) once, for:")?;
            for step in &root.summary {
                outln!("  - {step}")?;
            }
            if !interactive || !key::ask("Set these up with sudo?", true)? {
                outln!()?;
                outln!("Run this script, then `pqkey setup` again:")?;
                outln!()?;
                outln!("    sudo sh {}", path.display())?;
                return Ok(());
            }
        }
        run_as_root("sudo", &path)?;
        let _ = fs::remove_file(&path);
        for step in &root.summary {
            output::done(step)?;
        }
    }
    // The script may have added this user to the group.
    let membership = checks::membership();
    if checks::needs_login(&system, &membership) {
        // The key starts by itself once the new session has the group.
        install_unit(&binary)?;
        systemctl(&["enable", UNIT])?;
        return output::problem(
            format!("this session started before you joined '{UHID_GROUP}'"),
            "log out and in again: the key then starts by itself, and `pqkey pin` sets its PIN",
        );
    }
    let problems = checks::start_problems(&system, &membership);
    if !problems.is_empty() {
        output::problems(&problems)?;
        outln!()?;
        outln!("The key cannot start yet: fix the above, then run `pqkey setup` again.")?;
        return Ok(());
    }

    let changed = install_unit(&binary)?;
    systemctl(&["enable", UNIT])?;
    // A unit that failed to start too often refuses to start until this.
    let _ = systemctl(&["reset-failed", UNIT]);
    let running = match daemon::running(state_dir)? {
        // The service runs it from now on.
        Some(Running::Daemon(_)) => {
            daemon::unplug(state_dir)?;
            None
        }
        running => running,
    };
    let (running, how) = match running {
        // A new unit, or a new binary in place of the one the service runs.
        Some(Running::Service(pid)) if changed || runs_another_binary(pid, &binary) => {
            (daemon::replug(state_dir)?, "restarted")
        }
        Some(running) => (running, "running"),
        None => (
            daemon::plug_in(state_dir, &super::DaemonArgs::default())?,
            "started",
        ),
    };
    output::done(format_args!("Key {how}; it starts with your session"))?;

    let mut problems = key::running_problems(&system, running, Duration::from_secs(5));
    problems.extend(path_problem(&binary, env::var_os("PATH").as_deref()));
    output::problems(&problems)?;
    let has_pin = match key::ensure_pin(running, interactive) {
        Ok(has_pin) => has_pin,
        Err(err) => {
            output::problem(format!("the PIN is not set: {err}"), "run `pqkey pin`")?;
            false
        }
    };
    finish(problems.is_empty() && has_pin)
}

/// The last words of setup: whether the key is ready, and the commands to
/// use it with.
fn finish(ready: bool) -> io::Result<()> {
    outln!()?;
    if ready {
        outln!(
            "pqkey is ready. Use it on any site that supports passkeys or security keys, and \
             approve the desktop notification that appears."
        )?;
    } else {
        outln!("pqkey is almost ready: fix what is marked with ! above.")?;
    }
    outln!()?;
    for (command, what) in [
        ("pqkey", "the key's status"),
        ("pqkey passkeys", "your passkeys"),
        ("pqkey --help", "every command"),
    ] {
        outln!("  {command:<16} {what}")?;
    }
    Ok(())
}

/// Whether the process `pid` runs another file than `binary`: `cargo
/// install` replaced it, and `/proc` names the old file as deleted.
fn runs_another_binary(pid: unistd::Pid, binary: &Path) -> bool {
    fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| exe != binary)
}

/// Run `script` as root with `sudo` (or, in tests, another program), which
/// asks for the user's password on the terminal.
fn run_as_root(sudo: &str, script: &Path) -> io::Result<()> {
    let rerun = format!(
        "run `sudo sh {}`, then `pqkey setup` again",
        script.display()
    );
    let status = std::process::Command::new(sudo)
        .arg("sh")
        .arg(script)
        .status()
        .map_err(|err| io::Error::new(err.kind(), format!("cannot run {sudo}: {err}; {rerun}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the steps that need root did not finish ({status}); {rerun}"
        )))
    }
}

/// Install the unit for `binary` and have systemd read it, unless it is
/// installed as it is. Returns whether it changed.
fn install_unit(binary: &Path) -> io::Result<bool> {
    let unit = unit_file(binary)?;
    let dir = unit_dir();
    let path = dir.join(UNIT);
    if fs::read_to_string(&path).is_ok_and(|installed| installed == unit) {
        return Ok(false);
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
    systemctl(&["daemon-reload"])?;
    Ok(true)
}

fn systemctl(args: &[&str]) -> io::Result<()> {
    daemon::systemctl(args).map(drop)
}

/// Whether `pqkey`, run from the shell, is `binary`, as the README's
/// commands assume: an older pqkey earlier on the PATH would run instead.
fn path_problem(binary: &Path, path: Option<&OsStr>) -> Option<checks::Problem> {
    let dir = binary.parent()?;
    let found = path.and_then(|path| {
        env::split_paths(path)
            .map(|entry| entry.join("pqkey"))
            .find(|candidate| is_executable(candidate))
    });
    match found {
        Some(found) if found.canonicalize().is_ok_and(|found| found == binary) => None,
        Some(found) => Some(checks::Problem {
            what: format!(
                "`pqkey` runs {}, not {}, which the service runs",
                found.display(),
                binary.display()
            ),
            fix: format!(
                "remove {} if it is an older pqkey, or put {} first on your PATH",
                found.display(),
                dir.display()
            ),
        }),
        None => Some(checks::Problem {
            what: format!("{} is not on your PATH", dir.display()),
            fix: "add it in your shell's profile, or log in again if your profile adds it".into(),
        }),
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// `pqkey setup --uninstall`.
pub fn uninstall(state_dir: &Path) -> io::Result<()> {
    check_caller(state_dir)?;
    if daemon::unplug(state_dir)?.is_some() {
        output::done("Key stopped")?;
    }
    let path = unit_dir().join(UNIT);
    if path.exists() {
        // Disabling an installed unit cannot fail for a reason worth stopping
        // for: removing it is what matters.
        let _ = systemctl(&["disable", UNIT]);
        fs::remove_file(&path)?;
        systemctl(&["daemon-reload"])?;
        output::done(format_args!("Removed {}", path.display()))?;
    }
    let binary = env::current_exe()?.canonicalize()?;
    let script = root_undo_script(&binary);
    let script_path = hand_over(&runtime_dir(), &script, "pqkey-uninstall.sh")?;
    outln!()?;
    if binary == Path::new(INSTALLED_BINARY) {
        outln!("To remove pqkey itself, its udev rules and the uhid setting too, run:")?;
    } else {
        outln!("To remove the udev rules and the uhid setting too, run:")?;
    }
    outln!()?;
    outln!("    sudo sh {}", script_path.display())?;
    outln!()?;
    outln!(
        "Your passkeys and PIN stay in {}; delete it to remove them for good. Your \
         membership in '{UHID_GROUP}' stays too.",
        state_dir.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn membership(member: bool, group_exists: bool) -> Membership {
        Membership {
            user: "o'brien".into(),
            group_exists,
            member,
            in_session: member,
        }
    }

    #[test]
    fn an_older_pqkey_earlier_on_the_path_is_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("setup-path");
        let (old, new, none) = (
            dir.path().join("old"),
            dir.path().join("new"),
            dir.path().join("none"),
        );
        for bin in [&old, &new] {
            fs::create_dir_all(bin).unwrap();
            fs::write(bin.join("pqkey"), "").unwrap();
            fs::set_permissions(bin.join("pqkey"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(&none).unwrap();
        let binary = new.join("pqkey").canonicalize().unwrap();
        let path = |dirs: &[&PathBuf]| env::join_paths(dirs).unwrap();

        assert_eq!(
            path_problem(&binary, Some(&path(&[&none, &new, &old]))),
            None
        );
        let shadowed = path_problem(&binary, Some(&path(&[&old, &new]))).unwrap();
        assert!(shadowed.what.contains("old/pqkey"), "{shadowed:?}");
        assert!(shadowed.fix.starts_with("remove "), "{shadowed:?}");
        let missing = path_problem(&binary, Some(&path(&[&none]))).unwrap();
        assert!(missing.what.ends_with("is not on your PATH"), "{missing:?}");
        assert!(path_problem(&binary, None).is_some());
    }

    #[test]
    fn a_failed_root_step_says_how_to_run_it_again() {
        let script = Path::new("/run/user/1000/pqkey-setup.sh");
        run_as_root("true", script).unwrap();
        let err = run_as_root("false", script).unwrap_err();
        assert!(
            err.to_string()
                .contains("run `sudo sh /run/user/1000/pqkey-setup.sh`"),
            "{err}"
        );
        let err = run_as_root("/nonexistent/sudo", script).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }

    // It reads /proc, which only Linux has.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_service_running_a_replaced_binary_is_restarted() {
        let me = unistd::Pid::this();
        let exe = env::current_exe().unwrap().canonicalize().unwrap();
        assert!(!runs_another_binary(me, &exe));
        assert!(runs_another_binary(me, Path::new("/usr/bin/pqkey")));
    }

    #[test]
    fn setup_is_for_the_default_state_directory_only() {
        let err = check_caller(Path::new("/elsewhere")).unwrap_err();
        if !unistd::geteuid().is_root() {
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        }
    }

    #[test]
    fn the_unit_runs_the_installed_binary() {
        let unit = unit_file(Path::new("/home/a/.cargo/bin/pqkey")).unwrap();
        let exec: Vec<&str> = unit
            .lines()
            .filter(|l| l.starts_with("ExecStart="))
            .collect();
        assert_eq!(exec, ["ExecStart=/home/a/.cargo/bin/pqkey run"]);
        assert_eq!(unit.lines().count(), UNIT_TEMPLATE.lines().count());
        assert!(unit.contains("RestartPreventExitStatus=3"));

        let unit = unit_file(Path::new("/home/a b/100%/pqkey")).unwrap();
        assert!(
            unit.contains("\nExecStart=\"/home/a b/100%%/pqkey\" run\n"),
            "{unit}"
        );
        assert!(unit_file(Path::new("/home/a\nExecStartPre=/bin/x/pqkey")).is_err());
    }

    #[test]
    fn a_fresh_system_gets_one_root_script_with_every_step() {
        let dir = TempDir::new("setup-fresh");
        let system = System::under(dir.path().to_owned());
        let script = root_script(&system, &membership(false, false))
            .unwrap()
            .script;
        assert!(script.starts_with("#!/bin/sh\n"), "{script}");
        for step in [
            "cat > /etc/udev/rules.d/70-pqkey.rules <<'PQKEY_UDEV_RULES'\n",
            "\nPQKEY_UDEV_RULES\nchmod 644 /etc/udev/rules.d/70-pqkey.rules\n",
            "udevadm control --reload-rules\n",
            "echo uhid > /etc/modules-load.d/pqkey.conf\n",
            "modprobe uhid\n",
            "groupadd --system plugdev\n",
            "usermod -aG plugdev 'o'\\''brien'\n",
            "udevadm trigger --action=change --subsystem-match=hidraw\n",
            "then setfacl -m u:'o'\\''brien':rw /dev/uhid; fi\n",
        ] {
            assert!(script.contains(step), "{step}\n{script}");
        }
        // The rules arrive as shipped, inside a quoted here-document.
        assert!(script.contains(UDEV_RULES), "{script}");
        assert!(!UDEV_RULES.contains("PQKEY_UDEV_RULES"));
        assert!(UDEV_RULES.ends_with('\n'));
    }

    #[test]
    fn the_user_sees_what_root_sets_up_a_line_each() {
        let dir = TempDir::new("setup-summary");
        let system = System::under(dir.path().to_owned());
        let root = root_script(&system, &membership(false, true)).unwrap();
        assert_eq!(
            root.summary,
            [
                "udev rules for /dev/uhid and the key's device",
                "uhid module, loaded now and at every boot",
                "'plugdev' group for o'brien, which may open /dev/uhid",
            ]
        );
        fs::create_dir_all(system.path("/sys/class/misc/uhid")).unwrap();
        let root = root_script(&system, &membership(true, true)).unwrap();
        assert_eq!(
            root.summary[1..],
            ["uhid module, loaded at every boot".to_owned()]
        );
    }

    #[test]
    fn a_set_up_system_needs_no_root() {
        let dir = TempDir::new("setup-done");
        let system = System::under(dir.path().to_owned());
        for (path, text) in [
            (UDEV_RULES_PATH, UDEV_RULES),
            ("/etc/modules-load.d/uhid.conf", "uhid\n"),
            ("/sys/class/misc/uhid/dev", "10:239\n"),
            ("/dev/uhid", ""),
        ] {
            let path = system.path(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        assert_eq!(root_script(&system, &membership(true, true)), None);
        // Only what is missing: the group, on Ubuntu where it exists.
        let script = root_script(&system, &membership(false, true))
            .unwrap()
            .script;
        assert!(
            !script.contains("groupadd") && !script.contains("udev.rules"),
            "{script}"
        );
        assert!(script.contains("usermod -aG plugdev"), "{script}");
        assert!(script.contains("setfacl -m u:"), "{script}");
        // A member opens it through the group already.
        let script = root_script(
            &System::under(dir.path().join("none")),
            &membership(true, true),
        )
        .unwrap()
        .script;
        assert!(!script.contains("setfacl"), "{script}");
    }

    #[test]
    fn a_device_node_without_the_module_gets_the_module_loaded() {
        let dir = TempDir::new("setup-static-node");
        let system = System::under(dir.path().to_owned());
        for (path, text) in [
            (UDEV_RULES_PATH, UDEV_RULES),
            ("/etc/modules-load.d/uhid.conf", "uhid\n"),
            ("/dev/uhid", ""),
        ] {
            let path = system.path(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        let root = root_script(&system, &membership(true, true)).unwrap();
        assert!(root.script.contains("\nmodprobe uhid\n"), "{root:?}");
        assert_eq!(root.summary, ["uhid module, loaded now"]);
    }

    #[test]
    fn uninstalling_removes_what_setup_installed_as_root() {
        let script = root_undo_script(Path::new("/home/a/.cargo/bin/pqkey"));
        assert!(
            script.contains(
                "rm -f /etc/udev/rules.d/70-pqkey.rules /etc/modules-load.d/pqkey.conf\n"
            )
        );
        assert!(!script.contains("/usr/local/bin"), "{script}");
        let script = root_undo_script(Path::new("/usr/local/bin/pqkey"));
        assert!(
            script.ends_with("\nrm -f /usr/local/bin/pqkey\n"),
            "{script}"
        );
    }

    #[test]
    fn scripts_are_written_for_this_user_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("setup-handover");
        let path = hand_over(dir.path(), "#!/bin/sh\n", "pqkey-setup.sh").unwrap();
        assert_eq!(path, dir.path().join("pqkey-setup.sh"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Run again, it replaces the old script.
        hand_over(dir.path(), "#!/bin/sh\ntrue\n", "pqkey-setup.sh").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "#!/bin/sh\ntrue\n");
    }
}
