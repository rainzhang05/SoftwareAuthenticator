//! What the key needs from the system, and what is missing: the checks of
//! `pqkey status` and `pqkey setup`.
//!
//! Each check reads files under a root directory, `/` on the real system and
//! a temporary directory in tests, and a problem it finds names its fix.

use std::{
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

use nix::unistd::{self, Gid, Group, User};

use crate::presence::notification::{ConnectError, ServerInfo};

/// The udev rules this version of pqkey ships.
pub const UDEV_RULES: &str = include_str!("../../../../../contrib/udev/70-pqkey.rules");
/// Where `pqkey setup` installs [`UDEV_RULES`].
pub const UDEV_RULES_PATH: &str = "/etc/udev/rules.d/70-pqkey.rules";
/// Where `pqkey setup` has uhid loaded at boot.
pub const MODULES_LOAD_PATH: &str = "/etc/modules-load.d/pqkey.conf";
/// The group the udev rules give `/dev/uhid` to.
pub const UHID_GROUP: &str = "plugdev";

pub(crate) use crate::cli::checks::Problem;

/// The system the checks look at, under a root directory.
#[derive(Clone, Debug)]
pub struct System {
    root: PathBuf,
    membership: Option<Membership>,
}

/// Whether the udev rules are installed, and as this version ships them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rules {
    Missing,
    Outdated,
    Current,
}

/// The user's membership in [`UHID_GROUP`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The user's name.
    pub user: String,
    /// The group exists.
    pub group_exists: bool,
    /// The group database lists the user in the group.
    pub member: bool,
    /// This process has the group: the session started after the user
    /// joined it.
    pub in_session: bool,
}

/// A browser packaged as a snap, which can only open devices tagged for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapBrowser {
    pub name: &'static str,
    /// The snap.
    pub snap: &'static str,
    /// The udev tag that admits the snap's app to a device.
    pub tag: &'static str,
}

/// The browsers the udev rules tag the key's node for.
pub const SNAP_BROWSERS: [SnapBrowser; 2] = [
    SnapBrowser {
        name: "Firefox",
        snap: "firefox",
        tag: "snap_firefox_firefox",
    },
    SnapBrowser {
        name: "Chromium",
        snap: "chromium",
        tag: "snap_chromium_chromium",
    },
];

impl System {
    /// The running system.
    pub fn real() -> io::Result<Self> {
        Ok(Self::under(PathBuf::from("/")))
    }

    /// A system whose root directory is `root`.
    pub fn under(root: PathBuf) -> Self {
        Self {
            root,
            membership: None,
        }
    }

    /// `path`, an absolute path on the system, under the root.
    pub fn path(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    /// Whether the udev rules are installed, in `/etc` or where a package
    /// puts them, and whether they are this version's.
    pub fn rules(&self) -> Rules {
        let mut found = Rules::Missing;
        for dir in [
            "/etc/udev/rules.d",
            "/usr/lib/udev/rules.d",
            "/lib/udev/rules.d",
        ] {
            match fs::read_to_string(self.path(dir).join("70-pqkey.rules")) {
                Ok(text) if text == UDEV_RULES => return Rules::Current,
                Ok(_) => found = Rules::Outdated,
                Err(_) => {}
            }
        }
        found
    }

    /// Whether uhid is loaded at boot: a modules-load.d file, or
    /// `/etc/modules`, names it, or the kernel has it built in.
    pub fn uhid_at_boot(&self) -> bool {
        let names_uhid = |text: &str| {
            text.lines()
                .map(|line| line.split('#').next().unwrap_or("").trim())
                .any(|module| module == "uhid")
        };
        let configured = [
            "/etc/modules-load.d",
            "/run/modules-load.d",
            "/usr/local/lib/modules-load.d",
            "/usr/lib/modules-load.d",
            "/lib/modules-load.d",
        ]
        .iter()
        .filter_map(|dir| fs::read_dir(self.path(dir)).ok())
        .flatten()
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "conf"))
        .any(|entry| fs::read_to_string(entry.path()).is_ok_and(|text| names_uhid(&text)));
        configured
            || fs::read_to_string(self.path("/etc/modules")).is_ok_and(|text| names_uhid(&text))
            || self.uhid_built_in()
    }

    fn uhid_built_in(&self) -> bool {
        let Ok(release) = fs::read_to_string(self.path("/proc/sys/kernel/osrelease")) else {
            return false;
        };
        fs::read_to_string(
            self.path("/lib/modules")
                .join(release.trim())
                .join("modules.builtin"),
        )
        .is_ok_and(|text| text.lines().any(|line| line.ends_with("/uhid.ko")))
    }

    /// Whether the uhid module is loaded, or built in: its misc device is
    /// registered. `/dev/uhid` alone says nothing, as kmod creates it at boot
    /// for the module to be loaded on first open, which only root may do.
    pub fn uhid_loaded(&self) -> bool {
        self.path("/sys/class/misc/uhid").exists() || self.path("/sys/module/uhid").exists()
    }

    /// Open `/dev/uhid` as the daemon does.
    pub fn open_uhid(&self) -> io::Result<()> {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path("/dev/uhid"))
            .map(drop)
    }

    /// The snap browsers installed.
    pub fn snap_browsers(&self) -> Vec<SnapBrowser> {
        SNAP_BROWSERS
            .into_iter()
            .filter(|browser| {
                ["/snap", "/var/lib/snapd/snap"]
                    .iter()
                    .any(|dir| self.path(dir).join(browser.snap).join("current").exists())
            })
            .collect()
    }

    /// The udev tags of the hidraw node `node` (such as `/dev/hidraw3`), from
    /// udev's database, or `None` if udev has no record of it.
    pub fn node_tags(&self, node: &Path) -> Option<Vec<String>> {
        let name = node.file_name()?.to_str()?;
        let number =
            fs::read_to_string(self.path("/sys/class/hidraw").join(name).join("dev")).ok()?;
        let record = fs::read_to_string(
            self.path("/run/udev/data")
                .join(format!("c{}", number.trim())),
        )
        .ok()?;
        Some(
            record
                .lines()
                .filter_map(|line| line.strip_prefix("G:").or_else(|| line.strip_prefix("Q:")))
                .map(str::to_owned)
                .collect(),
        )
    }
}

/// This user's membership in [`UHID_GROUP`].
pub fn membership() -> Membership {
    let user = User::from_uid(unistd::getuid())
        .ok()
        .flatten()
        .map(|user| (user.name, user.gid));
    let group = Group::from_name(UHID_GROUP).ok().flatten();
    let (name, primary) = user.unwrap_or_else(|| (String::new(), Gid::from_raw(u32::MAX)));
    let Some(group) = group else {
        return Membership {
            user: name,
            group_exists: false,
            member: false,
            in_session: false,
        };
    };
    // nix does not expose getgroups on Apple platforms. The daemon only runs
    // on Linux (it needs /dev/uhid).
    #[cfg(target_os = "linux")]
    let groups = unistd::getgroups().unwrap_or_default();
    #[cfg(not(target_os = "linux"))]
    let groups: Vec<Gid> = Vec::new();
    Membership {
        member: primary == group.gid || group.mem.contains(&name),
        in_session: unistd::getegid() == group.gid || groups.contains(&group.gid),
        user: name,
        group_exists: true,
    }
}

/// What keeps the key from starting, as far as the system goes: the uhid
/// module, the udev rules and the group that may open `/dev/uhid`.
pub fn start_problems(system: &System, membership: &Membership) -> Vec<Problem> {
    let mut problems = Vec::new();
    let setup = "run `pqkey setup`";
    match system.rules() {
        Rules::Missing => {
            problems.push(Problem::new("pqkey's udev rules are not installed", setup))
        }
        Rules::Outdated => problems.push(Problem::new(
            format!("the udev rules in {UDEV_RULES_PATH} are not this version's"),
            setup,
        )),
        Rules::Current => {}
    }
    if !system.uhid_at_boot() {
        problems.push(Problem::new("the uhid module is not loaded at boot", setup));
    }
    if !system.uhid_loaded() {
        problems.push(Problem::new("the uhid module is not loaded", setup));
        return problems;
    }
    match system.open_uhid() {
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            problems.push(if membership.member && !membership.in_session {
                Problem::new(
                    format!(
                        "this session started before you joined '{UHID_GROUP}', so it cannot open \
                         /dev/uhid"
                    ),
                    "log out and in again",
                )
            } else if membership.member {
                Problem::new(
                    format!("you are in '{UHID_GROUP}' but cannot open /dev/uhid"),
                    setup,
                )
            } else {
                Problem::new(
                    format!("you are not in '{UHID_GROUP}', which may open /dev/uhid"),
                    setup,
                )
            });
        }
        Err(err) => problems.push(Problem::new(format!("cannot open /dev/uhid: {err}"), setup)),
        Ok(()) => {}
    }
    problems
}

/// Whether all that keeps the key from starting is a session older than the
/// user's membership in [`UHID_GROUP`], which logging in again fixes.
pub fn needs_login(system: &System, membership: &Membership) -> bool {
    membership.member
        && !membership.in_session
        && system.rules() == Rules::Current
        && system.uhid_at_boot()
        && system.uhid_loaded()
        && system
            .open_uhid()
            .is_err_and(|err| err.kind() == ErrorKind::PermissionDenied)
}

/// What keeps browsers from opening the running key's node `node`.
pub fn browser_problems(system: &System, node: &Path, opened: &io::Result<()>) -> Vec<Problem> {
    let mut problems = Vec::new();
    if let Err(err) = opened {
        problems.push(Problem::new(
            format!("you cannot open the key's device {}: {err}", node.display()),
            if err.kind() == ErrorKind::PermissionDenied {
                "run `pqkey setup`; over SSH, or outside the active local session, browsers there \
                 cannot use the key"
            } else {
                "run `pqkey stop && pqkey start`"
            },
        ));
    }
    let tags = system.node_tags(node).unwrap_or_default();
    for browser in system.snap_browsers() {
        if !tags.iter().any(|tag| tag == browser.tag) {
            problems.push(Problem::new(
                format!(
                    "{} is a snap and cannot open the key: its device is not tagged {}",
                    browser.name, browser.tag
                ),
                "run `pqkey setup`, then `pqkey stop && pqkey start`",
            ));
        }
    }
    problems
}

/// Whether the desktop can ask for approval: a notification server with
/// action buttons and a body, without which every request is denied.
pub fn notification_problem(server: &Result<ServerInfo, ConnectError>) -> Option<Problem> {
    let denied = "so every registration, sign-in and reset is denied";
    match server {
        Err(ConnectError::NoSession(err)) => Some(Problem::new(
            format!("there is no D-Bus session bus ({err}), {denied}"),
            "run pqkey in your desktop session",
        )),
        Err(ConnectError::NoServer(_)) => Some(Problem::new(
            format!("no desktop notification server is running, {denied}"),
            "use a desktop with notifications that have buttons, such as GNOME, KDE Plasma or \
             dunst",
        )),
        Err(ConnectError::Failed(err)) => Some(Problem::new(
            format!("the notification server cannot be reached ({err}), {denied}"),
            "check `journalctl --user -u pqkey`",
        )),
        Ok(info) => {
            let missing: Vec<&str> = ["actions", "body"]
                .into_iter()
                .filter(|capability| match *capability {
                    "actions" => !info.supports_actions,
                    _ => !info.supports_body,
                })
                .collect();
            (!missing.is_empty()).then(|| {
                Problem::new(
                    format!(
                        "the notification server ({}) cannot show {}, {denied}",
                        info.name.as_deref().unwrap_or("unnamed"),
                        missing.join(" or ")
                    ),
                    "use a notification server with buttons, such as GNOME, KDE Plasma or dunst",
                )
            })
        }
    }
}

impl System {
    pub fn check_setup_caller(state_dir: &Path) -> io::Result<()> {
        super::setup::check_caller(state_dir)
    }
    pub fn refresh(&mut self) -> io::Result<()> {
        self.membership = Some(membership());
        Ok(())
    }
    pub fn setup_steps(&self) -> io::Result<Option<crate::platform::SetupSteps>> {
        let member = self.membership.clone().unwrap_or_else(membership);
        let Some(root) = super::setup::root_script(self, &member) else {
            return Ok(None);
        };
        let artifact =
            super::setup::hand_over(&super::setup::runtime_dir(), &root.script, "pqkey-setup.sh")?;
        let instructions = vec![
            String::new(),
            "Run this script, then `pqkey setup` again:".into(),
            String::new(),
            format!("    sudo sh {}", artifact.display()),
        ];
        Ok(Some(crate::platform::SetupSteps {
            summary: root.summary,
            heading: "Setup needs root (sudo) once, for:",
            question: "Set these up with sudo?",
            instructions,
            artifact,
        }))
    }
    pub fn apply_setup_steps(&self, steps: &crate::platform::SetupSteps) -> io::Result<()> {
        super::setup::run_as_root("sudo", &steps.artifact)?;
        let _ = fs::remove_file(&steps.artifact);
        Ok(())
    }
    pub fn login_problem(&self) -> io::Result<Option<Problem>> {
        let member = self.membership.clone().unwrap_or_else(membership);
        Ok(needs_login(self, &member).then(|| {
            Problem::new(
                format!("this session started before you joined '{UHID_GROUP}'"),
                "log out and in again: the key then starts by itself, and `pqkey pin` sets its PIN",
            )
        }))
    }
    pub fn start_problems(&self) -> io::Result<Vec<Problem>> {
        let member = self.membership.clone().unwrap_or_else(membership);
        Ok(start_problems(self, &member))
    }
    pub fn device_problems(
        &self,
        pid: unistd::Pid,
        wait: std::time::Duration,
    ) -> io::Result<Vec<Problem>> {
        Ok(super::hidraw::device_problems(self, pid, wait))
    }
    pub fn notification_problem(
        &self,
        server: &Result<ServerInfo, ConnectError>,
    ) -> io::Result<Option<Problem>> {
        Ok(notification_problem(server))
    }
    pub fn uninstall_instructions(binary: &Path, state_dir: &Path) -> io::Result<Vec<String>> {
        let script = super::setup::root_undo_script(binary);
        let artifact =
            super::setup::hand_over(&super::setup::runtime_dir(), &script, "pqkey-uninstall.sh")?;
        let heading = if binary == Path::new(super::setup::INSTALLED_BINARY) {
            "To remove pqkey itself, its udev rules and the uhid setting too, run:"
        } else {
            "To remove the udev rules and the uhid setting too, run:"
        };
        Ok(vec![
            String::new(),
            heading.into(),
            String::new(),
            format!("    sudo sh {}", artifact.display()),
            String::new(),
            format!(
                "Your passkeys and PIN stay in {}; delete it to remove them for good. Your membership in '{UHID_GROUP}' stays too.",
                state_dir.display()
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn write(system: &System, path: &str, text: &str) {
        let path = system.path(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// The uhid module loaded: its misc device and its node.
    fn load_uhid(system: &System) {
        write(system, "/sys/class/misc/uhid/dev", "10:239\n");
        write(system, "/dev/uhid", "");
    }

    fn member() -> Membership {
        Membership {
            user: "alice".into(),
            group_exists: true,
            member: true,
            in_session: true,
        }
    }

    fn whats(problems: &[Problem]) -> Vec<&str> {
        problems
            .iter()
            .map(|problem| problem.what.as_str())
            .collect()
    }

    #[test]
    fn a_fresh_system_needs_everything() {
        let dir = TempDir::new("checks-fresh");
        let system = System::under(dir.path().to_owned());
        assert_eq!(system.rules(), Rules::Missing);
        assert!(!system.uhid_at_boot());
        assert_eq!(
            whats(&start_problems(&system, &member())),
            [
                "pqkey's udev rules are not installed",
                "the uhid module is not loaded at boot",
                "the uhid module is not loaded",
            ]
        );
    }

    #[test]
    fn a_set_up_system_has_no_problems() {
        let dir = TempDir::new("checks-ready");
        let system = System::under(dir.path().to_owned());
        write(&system, UDEV_RULES_PATH, UDEV_RULES);
        write(&system, MODULES_LOAD_PATH, "uhid\n");
        load_uhid(&system);
        assert_eq!(system.rules(), Rules::Current);
        assert_eq!(start_problems(&system, &member()), []);
    }

    #[test]
    fn a_device_node_without_the_module_is_not_loaded() {
        // kmod creates /dev/uhid at boot, root's, before uhid is loaded.
        let dir = TempDir::new("checks-static-node");
        let system = System::under(dir.path().to_owned());
        write(&system, "/dev/uhid", "");
        assert!(!system.uhid_loaded());
        load_uhid(&system);
        assert!(system.uhid_loaded());
    }

    #[test]
    fn rules_from_another_version_are_outdated() {
        let dir = TempDir::new("checks-outdated");
        let system = System::under(dir.path().to_owned());
        write(&system, UDEV_RULES_PATH, "SUBSYSTEM==\"misc\"\n");
        assert_eq!(system.rules(), Rules::Outdated);
        // A package's copy of this version's rules counts.
        write(&system, "/usr/lib/udev/rules.d/70-pqkey.rules", UDEV_RULES);
        assert_eq!(system.rules(), Rules::Current);
    }

    #[test]
    fn uhid_at_boot_is_found_wherever_it_is_configured() {
        for (path, text) in [
            ("/etc/modules-load.d/uhid.conf", "uhid\n"),
            (
                "/usr/lib/modules-load.d/x.conf",
                "# fido\n  uhid  # virtual keys\n",
            ),
            ("/etc/modules", "loop\nuhid\n"),
        ] {
            let dir = TempDir::new("checks-boot");
            let system = System::under(dir.path().to_owned());
            write(&system, path, text);
            assert!(system.uhid_at_boot(), "{path}");
        }
        let dir = TempDir::new("checks-boot-no");
        let system = System::under(dir.path().to_owned());
        write(
            &system,
            "/etc/modules-load.d/other.conf",
            "uhid_extra\n#uhid\n",
        );
        write(&system, "/etc/modules-load.d/uhid.txt", "uhid\n");
        assert!(!system.uhid_at_boot());
        // Built into the running kernel.
        write(&system, "/proc/sys/kernel/osrelease", "7.0.0-34-generic\n");
        write(
            &system,
            "/lib/modules/7.0.0-34-generic/modules.builtin",
            "kernel/drivers/hid/uhid.ko\n",
        );
        assert!(system.uhid_at_boot());
    }

    #[test]
    fn group_problems_name_their_fix() {
        let fix_for = |membership: Membership| {
            // A /dev/uhid this user may not open.
            let dir = TempDir::new("checks-group");
            let system = System::under(dir.path().to_owned());
            write(&system, UDEV_RULES_PATH, UDEV_RULES);
            write(&system, MODULES_LOAD_PATH, "uhid\n");
            load_uhid(&system);
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(system.path("/dev/uhid"), fs::Permissions::from_mode(0o000))
                .unwrap();
            start_problems(&system, &membership)
        };
        if unistd::geteuid().is_root() {
            return; // root opens anything
        }
        let relogin = fix_for(Membership {
            in_session: false,
            ..member()
        });
        assert_eq!(relogin.len(), 1, "{relogin:?}");
        assert_eq!(relogin[0].fix, "log out and in again");
        let outsider = fix_for(Membership {
            member: false,
            in_session: false,
            ..member()
        });
        assert!(
            outsider[0].what.contains("not in 'plugdev'"),
            "{outsider:?}"
        );
        assert_eq!(outsider[0].fix, "run `pqkey setup`");
    }

    #[test]
    fn only_a_session_older_than_the_membership_needs_a_new_login() {
        if unistd::geteuid().is_root() {
            return; // root opens anything
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("checks-login");
        let system = System::under(dir.path().to_owned());
        write(&system, UDEV_RULES_PATH, UDEV_RULES);
        write(&system, MODULES_LOAD_PATH, "uhid\n");
        load_uhid(&system);
        fs::set_permissions(system.path("/dev/uhid"), fs::Permissions::from_mode(0o000)).unwrap();
        let joined = Membership {
            in_session: false,
            ..member()
        };
        assert!(needs_login(&system, &joined));
        assert!(!needs_login(&system, &member()));
        assert!(!needs_login(
            &system,
            &Membership {
                member: false,
                ..joined.clone()
            }
        ));
        fs::remove_file(system.path(UDEV_RULES_PATH)).unwrap();
        assert!(!needs_login(&system, &joined), "the rules are missing too");
    }

    #[test]
    fn snap_browsers_need_the_node_tagged_for_them() {
        let dir = TempDir::new("checks-snap");
        let system = System::under(dir.path().to_owned());
        let node = Path::new("/dev/hidraw3");
        write(&system, "/sys/class/hidraw/hidraw3/dev", "240:3\n");
        write(
            &system,
            "/run/udev/data/c240:3",
            "E:ID_FIDO_TOKEN=1\nG:uaccess\nQ:uaccess\n",
        );
        // No snap browsers: nothing to tag for.
        assert_eq!(browser_problems(&system, node, &Ok(())), []);

        fs::create_dir_all(system.path("/snap/firefox/current")).unwrap();
        fs::create_dir_all(system.path("/var/lib/snapd/snap/chromium/current")).unwrap();
        assert_eq!(system.snap_browsers(), SNAP_BROWSERS);
        let problems = browser_problems(&system, node, &Ok(()));
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems[0].what.starts_with("Firefox is a snap"),
            "{problems:?}"
        );

        write(
            &system,
            "/run/udev/data/c240:3",
            "G:uaccess\nG:snap_firefox_firefox\nG:snap_chromium_chromium\n",
        );
        assert_eq!(browser_problems(&system, node, &Ok(())), []);
        let denied = Err(io::Error::from(ErrorKind::PermissionDenied));
        assert!(
            browser_problems(&system, node, &denied)[0]
                .what
                .starts_with("you cannot open the key's device /dev/hidraw3")
        );
    }

    #[test]
    fn notifications_need_buttons_and_a_body() {
        let server = |capabilities: &[&str]| {
            Ok(ServerInfo {
                supports_actions: capabilities.contains(&"actions"),
                supports_body: capabilities.contains(&"body"),
                name: Some("example".into()),
                ..ServerInfo::default()
            })
        };
        assert_eq!(
            notification_problem(&server(&["actions", "body", "persistence"])),
            None
        );
        let problem = notification_problem(&server(&["body"])).unwrap();
        assert!(
            problem.what.contains("(example) cannot show actions"),
            "{problem:?}"
        );
        let problem = notification_problem(&server(&[])).unwrap();
        assert!(
            problem.what.contains("cannot show actions or body"),
            "{problem:?}"
        );
        let none = notification_problem(&Err(ConnectError::NoServer("x".into()))).unwrap();
        assert!(
            none.what
                .contains("every registration, sign-in and reset is denied")
        );
    }

    #[test]
    fn the_rules_are_the_shipped_file() {
        assert!(UDEV_RULES.contains(r#"KERNEL=="uhid", GROUP="plugdev""#));
        assert!(UDEV_RULES.contains(r#"TAG+="snap_firefox_firefox""#));
    }
}
