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
    pub(crate) fn under(root: PathBuf) -> Self {
        Self {
            root,
            membership: None,
        }
    }

    /// `path`, an absolute path on the system, under the root.
    pub(crate) fn path(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    /// Whether the udev rules are installed, in `/etc` or where a package
    /// puts them, and whether they are this version's.
    pub(crate) fn rules(&self) -> Rules {
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
    pub(crate) fn uhid_at_boot(&self) -> bool {
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
    pub(crate) fn uhid_loaded(&self) -> bool {
        self.path("/sys/class/misc/uhid").exists() || self.path("/sys/module/uhid").exists()
    }

    /// Open `/dev/uhid` as the daemon does.
    pub(crate) fn open_uhid(&self) -> io::Result<()> {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path("/dev/uhid"))
            .map(drop)
    }

    /// The snap browsers installed.
    pub(crate) fn snap_browsers(&self) -> Vec<SnapBrowser> {
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
    pub(crate) fn node_tags(&self, node: &Path) -> Option<Vec<String>> {
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
    let groups = unistd::getgroups().unwrap_or_default();
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
                    "run `pqkey setup` to grant access in this session",
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

/// What every notification problem leads to.
const DENIED: &str = "so every registration, sign-in and reset is denied";

/// Where a key has no session bus it can use: give the user's service manager
/// the desktop's, which the user service starts with, and restart the key,
/// which reads its environment only when it starts. A key `pqkey start` runs
/// without the service takes the terminal's.
const IMPORT_BUS_FIX: &str = "in a terminal of your desktop session, run `systemctl --user \
    import-environment DBUS_SESSION_BUS_ADDRESS`, then `pqkey stop && pqkey start`";

/// The notification servers a fix suggests.
pub(crate) const SERVERS: &str = "such as GNOME, KDE Plasma or dunst";

/// Whether the desktop can ask for approval: a notification server with
/// action buttons and a body, without which every request is denied. `key_bus`
/// is the address of the running key's session bus, when that is the bus
/// `server` answered on; without it, it is this process's own. The key logs
/// the same with each request it denies (`notification::failure_message`).
pub fn notification_problem(
    server: &Result<ServerInfo, ConnectError>,
    key_bus: Option<&str>,
) -> Option<Problem> {
    let on = key_bus.map_or_else(String::new, |address| {
        format!(" on the key's session bus ({address})")
    });
    match server {
        Err(ConnectError::NoSession(err)) => Some(Problem::new(
            match key_bus {
                Some(_) => format!("the key cannot connect to its session bus ({err}), {DENIED}"),
                None => format!("there is no D-Bus session bus ({err}), {DENIED}"),
            },
            IMPORT_BUS_FIX,
        )),
        Err(ConnectError::NoServer(err)) => Some(Problem::new(
            match key_bus {
                Some(address) => format!(
                    "no desktop notification server answers on the key's session bus \
                     ({address}: {err}), {DENIED}"
                ),
                None => format!("no desktop notification server is running, {DENIED}"),
            },
            // A desktop may run its server on a bus of its own, as under
            // `dbus-run-session`, which the key then needs.
            format!(
                "use a desktop with notifications that have buttons, {SERVERS}{}",
                key_bus.map_or_else(String::new, |_| format!(
                    "; if yours has them, {IMPORT_BUS_FIX}"
                ))
            ),
        )),
        // The bus did not answer in time, or refused to pass the server's
        // answers on. The key's log says no more than this, and its denial
        // points back here, so the fix is not to read it.
        Err(ConnectError::Failed(err)) => Some(Problem::new(
            format!("the notification server{on} cannot be reached ({err}), {DENIED}"),
            "try again in a moment; if it keeps failing, log out and back in, or restart the \
             computer",
        )),
        Ok(info) => {
            let missing: Vec<&str> = [
                (!info.supports_actions).then_some("Approve and Deny buttons"),
                (!info.supports_body).then_some("notification text"),
            ]
            .into_iter()
            .flatten()
            .collect();
            (!missing.is_empty()).then(|| {
                Problem::new(
                    format!(
                        "the notification server ({}){on} cannot show {}, {DENIED}",
                        info.name.as_deref().unwrap_or("unnamed"),
                        missing.join(" or ")
                    ),
                    format!("use a notification server that shows buttons and text, {SERVERS}"),
                )
            })
        }
    }
}

/// Whether the running key can ask for approval on its session bus at
/// `address`: [`notification_problem`] for what `check` finds there, as the key
/// would. A bus over TCP is never connected to: connecting reads and sends the
/// nonce file the address may name, which the key's process can write. Such a
/// bus cannot be checked, nor can a key that recorded none, as one of an
/// older pqkey; the fix gives the user manager the desktop's bus and restarts
/// the key, which then records its bus.
pub fn key_notification_problem(
    address: Option<&str>,
    check: impl FnOnce(&str) -> Result<ServerInfo, ConnectError>,
) -> Option<Problem> {
    match address {
        Some(address) if !super::dbus::is_tcp_address(address) => {
            notification_problem(&check(address), Some(address))
        }
        _ => Some(Problem::new(
            format!(
                "pqkey cannot check whether the key can ask for approval on its session bus{}",
                address.map_or_else(String::new, |address| format!(" ({address})"))
            ),
            IMPORT_BUS_FIX,
        )),
    }
}

/// What the notification server on the session bus at `address` says about
/// itself.
fn server_at(address: &str) -> Result<ServerInfo, ConnectError> {
    use super::dbus::SessionBus;
    use crate::presence::notification::NotificationServer;
    let mut bus = SessionBus::at(address);
    let server = bus.connect();
    bus.disconnect();
    server
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
        Ok(Some(crate::platform::SetupSteps {
            summary: root.summary,
            heading: "Setup needs root (sudo) once, for:",
            question: "Set these up with sudo?",
            script: root.script,
        }))
    }
    pub fn apply_setup_steps(&self, steps: &crate::platform::SetupSteps) -> io::Result<()> {
        let artifact = super::setup::hand_over(
            &super::setup::runtime_dir(),
            &steps.script,
            "pqkey-setup.sh",
        )?;
        super::setup::run_as_root("sudo", &artifact)?;
        let _ = fs::remove_file(&artifact);
        Ok(())
    }
    pub fn login_problem(&self) -> io::Result<Option<Problem>> {
        let member = self.membership.clone().unwrap_or_else(membership);
        Ok(needs_login(self, &member).then(|| {
            Problem::new(
                format!("this session started before you joined '{UHID_GROUP}'"),
                "run `pqkey setup` to repair access in this session",
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
        Ok(notification_problem(server, None))
    }
    /// Whether the running key can ask for approval on its session bus, at
    /// `address`, connecting there as the key does: the free function of this
    /// name.
    pub fn key_notification_problem(&self, address: Option<&str>) -> io::Result<Option<Problem>> {
        Ok(key_notification_problem(address, server_at))
    }
    /// Whether a notification server on the session bus at `address` can ask
    /// for approval, connecting there as the key does: the check that
    /// `key_notification_problem` makes of the key's bus.
    pub fn can_ask_at(address: &str) -> bool {
        notification_problem(&server_at(address), Some(address)).is_none()
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
                "Your passkeys and PIN stay in {}; delete it to remove them for good. Your \
                 membership in '{UHID_GROUP}' stays too.",
                state_dir.display()
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, assert_problem};

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
        assert_eq!(
            relogin[0].fix,
            "run `pqkey setup` to grant access in this session"
        );
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

    /// A server that cannot show buttons, or text, is named with what it
    /// lacks.
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
            notification_problem(&server(&["actions", "body", "persistence"]), None),
            None
        );
        for (capabilities, cause) in [
            (&["body"][..], "cannot show Approve and Deny buttons,"),
            (
                &[],
                "cannot show Approve and Deny buttons or notification text",
            ),
            (&["actions"], "cannot show notification text"),
        ] {
            let problem = notification_problem(&server(capabilities), None).unwrap();
            assert_problem(&problem, &["(example)", cause, DENIED], &[SERVERS]);
        }
        let none = notification_problem(&Err(ConnectError::NoServer("x".into())), None).unwrap();
        assert!(
            none.what
                .contains("every registration, sign-in and reset is denied")
        );
    }

    /// No bus, or one that does not answer: fixes that act, never one that
    /// sends the user to the log, whose denial sends them back to status.
    #[test]
    fn a_missing_or_silent_bus_has_a_fix_of_its_own() {
        let none = notification_problem(&Err(ConnectError::NoSession("x".into())), None).unwrap();
        assert_eq!(
            none,
            Problem::new(
                "there is no D-Bus session bus (x), so every registration, sign-in and reset is \
                 denied",
                IMPORT_BUS_FIX
            )
        );
        assert_eq!(
            IMPORT_BUS_FIX,
            "in a terminal of your desktop session, run `systemctl --user import-environment \
             DBUS_SESSION_BUS_ADDRESS`, then `pqkey stop && pqkey start`"
        );
        let silent = notification_problem(&Err(ConnectError::Failed("timed out".into())), None);
        assert_eq!(
            silent,
            Some(Problem::new(
                "the notification server cannot be reached (timed out), so every registration, \
                 sign-in and reset is denied",
                "try again in a moment; if it keeps failing, log out and back in, or restart the \
                 computer"
            ))
        );
    }

    /// The running key's own bus is checked once, as the key would check it,
    /// and named with each problem and its fix. A bus over TCP is never
    /// connected to: it, and a key that recorded no bus, get the hint that
    /// status cannot check, with the fix that gives the key the desktop's
    /// bus, which a bus without a notification server gets too.
    #[test]
    fn the_keys_own_bus_is_checked_and_named_with_its_fix() {
        const KEY: &str = "unix:path=/run/user/1000/bus";
        const IMPORT: [&str; 2] = [
            "systemctl --user import-environment DBUS_SESSION_BUS_ADDRESS",
            "pqkey stop && pqkey start",
        ];
        let server = |actions: bool| {
            Ok(ServerInfo {
                supports_actions: actions,
                supports_body: true,
                name: Some("example".into()),
                ..ServerInfo::default()
            })
        };
        for (answer, cause, fix) in [
            (server(true), &[][..], &[][..]),
            (
                Err(ConnectError::NoSession("no socket".into())),
                &["the key cannot connect to its session bus", "no socket"],
                &IMPORT,
            ),
            (
                Err(ConnectError::NoServer("ServiceUnknown".into())),
                &[
                    "no desktop notification server answers",
                    KEY,
                    "ServiceUnknown",
                ],
                &[SERVERS, IMPORT[0], IMPORT[1]],
            ),
            (
                Err(ConnectError::Failed("did not answer".into())),
                &[
                    "the notification server on the key's session bus",
                    KEY,
                    "did not answer",
                ],
                &["try again"],
            ),
            (
                server(false),
                &[
                    "(example) on the key's session bus",
                    KEY,
                    "Approve and Deny buttons",
                ],
                &[SERVERS],
            ),
        ] {
            let mut checked = Vec::new();
            let problem = key_notification_problem(Some(KEY), |bus| {
                checked.push(bus.to_owned());
                answer
            });
            assert_eq!(checked, [KEY]);
            if cause.is_empty() {
                assert_eq!(problem, None);
            } else {
                assert_problem(&problem.unwrap(), &[cause, &[DENIED]].concat(), fix);
            }
        }
        for address in [
            Some("tcp:host=127.0.0.1,port=17171"),
            Some("nonce-tcp:host=localhost,port=1,noncefile=/tmp/nonce"),
            None,
        ] {
            let problem =
                key_notification_problem(address, |bus| panic!("connected to {bus}")).unwrap();
            let cause: Vec<&str> = ["cannot check", "session bus"]
                .into_iter()
                .chain(address)
                .collect();
            assert_problem(&problem, &cause, &IMPORT);
        }
    }

    #[test]
    fn the_rules_are_the_shipped_file() {
        assert!(UDEV_RULES.contains(r#"KERNEL=="uhid", GROUP="plugdev""#));
        assert!(UDEV_RULES.contains(r#"TAG+="snap_firefox_firefox""#));
    }
}
