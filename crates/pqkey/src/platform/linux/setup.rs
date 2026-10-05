//! `pqkey setup [--uninstall]`: install the key for this user, once.
//!
//! The user's part (the systemd user unit, starting the key, a PIN) is done
//! here. What needs root (the udev rules, loading uhid at boot, the group
//! that may open `/dev/uhid`) is written to a short script, summarised a line
//! a step, and run with `sudo sh` once the user agrees: pqkey itself never
//! runs as root.

use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use nix::unistd;

use super::checks::{
    MODULES_LOAD_PATH, Membership, Rules, System, UDEV_RULES, UDEV_RULES_PATH, UHID_GROUP,
};
#[cfg(test)]
use super::daemon::{UNIT_TEMPLATE, unit_file};
use crate::state::default_state_dir;

/// `text` as one shell word.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The steps of setup that need root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootSteps {
    /// The shell script that takes them.
    pub(crate) script: String,
    /// What they set up, a line each, to show the user.
    pub(crate) summary: Vec<String>,
}

/// The steps that need root, or `None` if none are left.
pub(crate) fn root_script(system: &System, membership: &Membership) -> Option<RootSteps> {
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
pub(crate) const INSTALLED_BINARY: &str = "/usr/local/bin/pqkey";

/// The steps that undo [`root_script`]'s, except the group membership, and
/// remove `binary` if install.sh installed it.
pub(crate) fn root_undo_script(binary: &Path) -> String {
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
pub(crate) fn runtime_dir() -> PathBuf {
    env::var_os("XDG_RUNTIME_DIR")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
}

/// Write `script` to `dir`/`name`, readable by this user only.
pub(crate) fn hand_over(dir: &Path, script: &str, name: &str) -> io::Result<PathBuf> {
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
pub(crate) fn check_caller(state_dir: &Path) -> io::Result<()> {
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

/// Run `script` as root with `sudo` (or, in tests, another program), which
/// asks for the user's password on the terminal.
pub(crate) fn run_as_root(sudo: &str, script: &Path) -> io::Result<()> {
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
        assert!(unit.contains("LimitCORE=0"));

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
