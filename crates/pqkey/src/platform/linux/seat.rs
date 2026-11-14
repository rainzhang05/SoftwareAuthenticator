//! logind's record of who is active on the key's seat, read and watched as
//! sd-login reads and watches it.
//!
//! logind keeps a file per seat in `/run/systemd/seats`. It writes every
//! state of a seat to a new file and moves that over the record: a temporary
//! file renamed into place. From systemd 258 the new file may start unnamed
//! (`O_TMPFILE`): it is linked in directly while there is no record, and
//! otherwise under a temporary name that is renamed into place. So a reader
//! sees one state or the next, and each state is a file of its own.
//! `ACTIVE_UID=` names the user of the active session and `ACTIVE=` the
//! session; neither is there while no session is active.
//! sd_seat_get_active(3) reads these two keys, and udev's `uaccess` builtin
//! gives a device to the user it returns. The file says it is private data,
//! but sd-login, the public interface, is these reads.
//!
//! A seat without a record is one logind does not have, to whose devices
//! udev gives no user: no logind, an empty directory that systemd-tmpfiles
//! made at boot, or a seat that does not exist yet. But logind removes a
//! record it had written in two cases: when the seat goes away, and, with
//! systemd 257 and older and with elogind, when it fails to save it, while
//! it goes on moving the seat's ACLs itself. So a record that the key has
//! seen since it started, by reading it or by a notification naming it, and
//! that is then missing, is one the key cannot tell the active session of,
//! not a seat with none; a record it has never seen counts as no seat.
//!
//! A look opens the record, takes the device and inode number from the open
//! file, and reads it through the same file, so identity and contents belong
//! together. It keeps that file open until the next look, so its inode is not
//! freed: a filesystem that gives the numbers of freed inodes to new ones, as
//! ext4 does, cannot give its number to a later record meanwhile. /run is
//! tmpfs, which numbers inodes from a counter instead and comes back to a
//! number only after about 2^32 others, or practically never with `inode64`.
//!
//! sd_login_monitor_new(3) watches the directory with inotify for files moved
//! into place or deleted; the key also watches for files created, which is
//! how a record that did not exist appears. The events only wake the key: it
//! reads the record whenever one waits, and compares files, not counts, so an
//! event that the kernel queues just after the new file became visible cannot
//! hide a state. Events naming the record are counted only to tell two
//! absences apart, since an absent record has no file to compare.
//!
//! The device's seat is its udev property `ID_SEAT`, or seat0 without one, as
//! udev's `uaccess` builtin takes it. udev records the property in its
//! database before that builtin gives the node to a user, so the key looks
//! it up from the moment the device is created, before every report until it
//! is found.

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read},
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::inotify::{AddWatchFlags, InitFlags, Inotify},
};

use crate::seat::{Active, Look, Record, SeatSource};

/// Where logind keeps its seats' records.
const SEATS: &str = "/run/systemd/seats";
/// The seat of a device udev gives none (`device_get_seat`).
const DEFAULT_SEAT: &str = "seat0";
/// How often a missing seats directory is looked for again.
const ABSENT_RECHECK: Duration = Duration::from_secs(1);
/// How long after a device is created its seat is looked up in udev's
/// database, and how often when no report has arrived.
const SEAT_LOOKUP_PATIENCE: Duration = Duration::from_secs(10);
const SEAT_LOOKUP_INTERVAL: Duration = Duration::from_millis(50);

/// The inotify events of the seats directory that change a record, or the
/// directory itself.
fn watch_mask() -> AddWatchFlags {
    AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_DELETE
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_MOVED_TO
        | AddWatchFlags::IN_DELETE_SELF
        | AddWatchFlags::IN_MOVE_SELF
        | AddWatchFlags::IN_ONLYDIR
}

/// Where the records are; tests use directories of their own.
struct Paths {
    seats: PathBuf,
    sys_hidraw: PathBuf,
    udev_data: PathBuf,
    recheck: Duration,
}

enum Watch {
    /// Events arrive through inotify.
    Notified(Inotify),
    /// The directory cannot be watched, so every question reads the record.
    Polled,
    /// The directory does not exist, so logind does not run; when it was
    /// last looked for, if it is not due again at once.
    Absent(Option<Instant>),
}

#[derive(Clone, Copy)]
enum Lookup {
    Done,
    /// Since when the device's seat has been looked for, and when it last
    /// was.
    Pending {
        since: Instant,
        tried: Option<Instant>,
    },
}

/// The seat of the key's device as logind records it.
pub struct SeatWatch {
    paths: Paths,
    uniq: String,
    seat: String,
    watch: Watch,
    /// The device turned out to be on another seat than the one watched.
    moved: bool,
    lookup: Lookup,
    /// How often an event named the record, events were lost, the watch
    /// was lost or regained, or the seat moved: what tells two absences of
    /// a record the key has not seen apart.
    changes: u64,
    /// The record the last look read, kept open so that its inode is not
    /// freed, nor its number given to a later record where freed numbers are
    /// given again.
    read: Option<File>,
    /// The seats whose record the key has read, or seen named in a
    /// notification, since it started.
    seen: HashSet<String>,
}

impl SeatWatch {
    /// Watch the seat of the devices whose HID unique identifier is `uniq`:
    /// seat0 until udev puts one on another. Logs how it watches.
    pub fn new(uniq: &str) -> Self {
        Self::at(
            Paths {
                seats: SEATS.into(),
                sys_hidraw: "/sys/class/hidraw".into(),
                udev_data: "/run/udev/data".into(),
                recheck: ABSENT_RECHECK,
            },
            uniq,
        )
    }

    fn at(paths: Paths, uniq: &str) -> Self {
        let mut watch = Self {
            paths,
            uniq: uniq.to_owned(),
            seat: DEFAULT_SEAT.to_owned(),
            watch: Watch::Absent(None),
            moved: false,
            lookup: Lookup::Done,
            changes: 0,
            read: None,
            seen: HashSet::new(),
        };
        watch.start();
        watch
    }

    /// Start watching the seats directory, and log how.
    fn start(&mut self) {
        let seats = self.paths.seats.display();
        // logind_running() in systemd: the `uaccess` builtin changes no ACL
        // without the directory.
        if !self.paths.seats.is_dir() {
            log::info!(
                "{seats} does not exist, so logind does not run and no session gets the key's \
                 device: the key keeps it"
            );
            self.watch = Watch::Absent(Some(Instant::now()));
            return;
        }
        let watched =
            Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).and_then(|inotify| {
                inotify
                    .add_watch(&self.paths.seats, watch_mask())
                    .map(|_| inotify)
            });
        self.watch = match watched {
            Ok(inotify) => {
                log::info!(
                    "watching {seats} for the session that is active on the key's seat: the key \
                     removes its device while another user's session is active there, and \
                     replaces it whenever logind saves the seat's record"
                );
                Watch::Notified(inotify)
            }
            Err(err) => {
                log::warn!(
                    "cannot watch {seats} ({err}): the key reads its seat's record there at every \
                     check instead, before each report it handles or sends and every 10 ms or so \
                     while idle"
                );
                Watch::Polled
            }
        };
    }

    /// Note that the watched seat's record has existed since the key
    /// started.
    fn saw(&mut self) {
        if !self.seen.contains(&self.seat) {
            self.seen.insert(self.seat.clone());
        }
    }

    /// Look the device's seat up in udev's database, as often as allowed,
    /// until it is found or the time for it is up. A seat other than the
    /// one watched is watched from now on.
    fn look_up_seat(&mut self, report: bool) {
        let Lookup::Pending { since, tried } = self.lookup else {
            return;
        };
        let now = Instant::now();
        if now.duration_since(since) > SEAT_LOOKUP_PATIENCE {
            log::debug!(
                "udev has not recorded the key's device; taking it to be on {}",
                self.seat
            );
            self.lookup = Lookup::Done;
            return;
        }
        if !report && tried.is_some_and(|at| now.duration_since(at) < SEAT_LOOKUP_INTERVAL) {
            return;
        }
        self.lookup = Lookup::Pending {
            since,
            tried: Some(now),
        };
        match node_seat(&self.paths.sys_hidraw, &self.paths.udev_data, &self.uniq) {
            Ok(None) => {}
            Ok(Some(seat)) => {
                self.lookup = Lookup::Done;
                if seat != self.seat {
                    log::info!(
                        "udev put the key's device on {seat}: watching that seat instead of {}",
                        self.seat
                    );
                    self.seat = seat;
                    self.moved = true;
                    self.changes += 1;
                }
            }
            Err(err) => log::debug!("cannot look up the key's seat in udev's database: {err}"),
        }
    }
}

impl SeatSource for SeatWatch {
    fn seat(&self) -> &str {
        &self.seat
    }

    fn changed(&mut self, report: bool) -> io::Result<bool> {
        self.look_up_seat(report);
        let (seats, recheck) = (&self.paths.seats, self.paths.recheck);
        let changed = match &mut self.watch {
            Watch::Notified(inotify) => readable(inotify)?,
            Watch::Polled => true,
            Watch::Absent(since) => {
                if since.is_some_and(|at| at.elapsed() < recheck) {
                    false
                } else if seats.is_dir() {
                    true
                } else {
                    *since = Some(Instant::now());
                    false
                }
            }
        };
        Ok(changed || self.moved)
    }

    fn look(&mut self) -> io::Result<Look> {
        if let Watch::Absent(_) = self.watch {
            if self.paths.seats.is_dir() {
                // logind started, or its directory came back, while the key
                // was not watching: what happened meanwhile is not known.
                self.changes += 1;
                self.start();
            } else {
                self.watch = Watch::Absent(Some(Instant::now()));
            }
        }
        self.moved = false;
        if let Watch::Notified(inotify) = &self.watch {
            let drained = drain(inotify, &self.seat)?;
            if drained.named {
                // The record existed, though it may be gone again.
                self.saw();
            }
            if drained.named || drained.lost {
                self.changes += 1;
            }
            if drained.gone {
                log::warn!(
                    "{} went away; looking for it again every {} s",
                    self.paths.seats.display(),
                    self.paths.recheck.as_secs()
                );
                self.watch = Watch::Absent(None);
                self.changes += 1;
            }
        }
        let absent = Look {
            active: Active::Nobody,
            record: Record::Absent(self.changes),
        };
        // sd-login refuses a seat name that is not a file name, and udev
        // then gives the device to nobody.
        if !is_file_name(&self.seat) {
            self.read = None;
            return Ok(absent);
        }
        let seen = self.seen.contains(&self.seat);
        match read_seat(&self.paths.seats, &self.seat, seen)? {
            Some((file, look)) => {
                self.saw();
                self.read = Some(file);
                Ok(look)
            }
            None => {
                self.read = None;
                Ok(absent)
            }
        }
    }

    fn wait(&mut self, timeout: Duration) -> io::Result<()> {
        match &self.watch {
            Watch::Notified(inotify) => {
                let mut fds = [PollFd::new(inotify.as_fd(), PollFlags::POLLIN)];
                match poll(
                    &mut fds,
                    PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX),
                ) {
                    Ok(_) | Err(Errno::EINTR) => Ok(()),
                    Err(err) => Err(err.into()),
                }
            }
            Watch::Polled | Watch::Absent(_) => {
                thread::sleep(timeout);
                Ok(())
            }
        }
    }

    fn plugged(&mut self) {
        self.lookup = Lookup::Pending {
            since: Instant::now(),
            tried: None,
        };
    }
}

/// Whether events are waiting on `inotify`.
fn readable(inotify: &Inotify) -> io::Result<bool> {
    let mut fds = [PollFd::new(inotify.as_fd(), PollFlags::POLLIN)];
    loop {
        match poll(&mut fds, PollTimeout::ZERO) {
            Ok(ready) => return Ok(ready > 0),
            Err(Errno::EINTR) => {}
            Err(err) => return Err(err.into()),
        }
    }
}

/// What the events drained since the last look showed.
struct Drained {
    /// One named the record `seat`.
    named: bool,
    /// Events were lost.
    lost: bool,
    /// The watch went away with the directory.
    gone: bool,
}

/// Read every event waiting on `inotify`.
fn drain(inotify: &Inotify, seat: &str) -> io::Result<Drained> {
    let mut drained = Drained {
        named: false,
        lost: false,
        gone: false,
    };
    loop {
        let events = match inotify.read_events() {
            Ok(events) => events,
            Err(Errno::EAGAIN) => return Ok(drained),
            Err(Errno::EINTR) => continue,
            Err(err) => return Err(err.into()),
        };
        for event in events {
            if event.mask.intersects(
                AddWatchFlags::IN_IGNORED
                    | AddWatchFlags::IN_DELETE_SELF
                    | AddWatchFlags::IN_MOVE_SELF
                    | AddWatchFlags::IN_UNMOUNT,
            ) {
                drained.gone = true;
            } else if event.mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
                drained.lost = true;
            } else if event.name.as_deref() == Some(OsStr::new(seat)) {
                drained.named = true;
            }
        }
    }
}

/// Open the seat's record at `path` and read it: the open file, and what it
/// says, with its identity. `None` without a record, for which sd-login
/// returns ENXIO and udev's `uaccess` builtin gives the device to no user.
fn read_record(path: &Path) -> io::Result<Option<(File, Look)>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let metadata = file.metadata()?;
    let mut contents = String::new();
    (&file).read_to_string(&mut contents)?;
    let look = Look {
        active: parse_active(&contents),
        record: Record::File {
            dev: metadata.dev(),
            ino: metadata.ino(),
        },
    };
    Ok(Some((file, look)))
}

/// Read the record of `seat` in the seats directory `seats`, as
/// [`read_record`] does. A missing record is `None`, a seat to whose devices
/// udev gives no user, unless the key has `seen` it since it started: then
/// it is an error, since logind removes a record it wrote only when the seat
/// goes away or, with systemd 257 and older and with elogind, when a save
/// fails, and those go on moving the seat's ACLs themselves.
fn read_seat(seats: &Path, seat: &str, seen: bool) -> io::Result<Option<(File, Look)>> {
    let record = seats.join(seat);
    match read_record(&record)? {
        Some(found) => Ok(Some(found)),
        None if seen => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} has gone since the key saw it, as when logind cannot save it or the seat \
                 goes away",
                record.display()
            ),
        )),
        None => Ok(None),
    }
}

/// Why logind's record of seat0 may keep the device of a key that runs
/// there unplugged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Held {
    /// Another user's session is active there.
    ByAnotherUser,
    /// The record cannot be read or understood, so the active session may be
    /// anyone's.
    Unreadable,
    /// The seats directory exists, but the record does not: the key keeps
    /// its device unplugged if it has seen the record since it started,
    /// which this process cannot tell.
    Missing,
}

/// Why logind's record of seat0, read as the key reads it, may keep the
/// device of a key that runs as `uid` on seat0 unplugged; `None` if it does
/// not.
pub(crate) fn seat0_held(uid: u32) -> Option<Held> {
    held_in(Path::new(SEATS), uid)
}

fn held_in(seats: &Path, uid: u32) -> Option<Held> {
    match read_record(&seats.join(DEFAULT_SEAT)) {
        Ok(Some((_, look))) => match look.active {
            Active::Session { uid: active, .. } if active != uid => Some(Held::ByAnotherUser),
            Active::Unknown => Some(Held::Unreadable),
            Active::Session { .. } | Active::Nobody => None,
        },
        Ok(None) if seats.is_dir() => Some(Held::Missing),
        Ok(None) => None,
        Err(_) => Some(Held::Unreadable),
    }
}

/// The active session in a seat's record, which logind writes as `KEY=value`
/// lines. sd-login reads `ACTIVE_UID` for the user udev gives the device to;
/// without it no session is active. logind writes it and `ACTIVE` together,
/// so a record with only one of them, or a user ID sd-login would refuse, is
/// one the key does not understand.
pub(crate) fn parse_active(contents: &str) -> Active {
    let (mut session, mut uid) = (None, None);
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with(['#', ';']) {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim_end() {
            "ACTIVE" => session = Some(value.trim()),
            "ACTIVE_UID" => uid = Some(value.trim()),
            _ => {}
        }
    }
    match (session, uid.map(parse_uid)) {
        (None, None) => Active::Nobody,
        (Some(id), Some(Some(uid))) => Active::Session {
            id: id.to_owned(),
            uid,
        },
        _ => Active::Unknown,
    }
}

/// A user ID as systemd's `parse_uid` takes one: decimal digits without a
/// sign or a leading zero, and neither the 32-bit nor the 16-bit -1.
fn parse_uid(text: &str) -> Option<u32> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse::<u32>()
        .ok()
        .filter(|&uid| uid != u32::MAX && uid != 0xFFFF)
}

/// Whether `name` can name a file in the seats directory, as sd-login's
/// `filename_is_valid` requires of a seat.
fn is_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 255
        && !name.contains(['/', '\0'])
}

/// The seat udev gave the hidraw node of the HID device whose unique
/// identifier is `uniq`, with sysfs's `class/hidraw` at `sys_hidraw` and
/// udev's database at `udev_data`: its `ID_SEAT`, or seat0 without one, as
/// `device_get_seat` in systemd takes it. `None` while there is no such
/// node, or udev has not recorded it yet.
fn node_seat(sys_hidraw: &Path, udev_data: &Path, uniq: &str) -> io::Result<Option<String>> {
    // Other HID devices have an empty unique identifier too.
    if uniq.is_empty() {
        return Ok(None);
    }
    let entries = match fs::read_dir(sys_hidraw) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    for entry in entries.flatten() {
        let Ok(uevent) = fs::read_to_string(entry.path().join("device").join("uevent")) else {
            continue;
        };
        if !uevent
            .lines()
            .any(|line| line.strip_prefix("HID_UNIQ=") == Some(uniq))
        {
            continue;
        }
        // The node's device numbers name its record: c<major>:<minor>.
        let Ok(numbers) = fs::read_to_string(entry.path().join("dev")) else {
            return Ok(None);
        };
        let record = match fs::read_to_string(udev_data.join(format!("c{}", numbers.trim()))) {
            Ok(record) => record,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let seat = record
            .lines()
            .filter_map(|line| line.strip_prefix("E:ID_SEAT="))
            .next_back()
            .filter(|seat| !seat.is_empty())
            .unwrap_or(DEFAULT_SEAT);
        return Ok(Some(seat.to_owned()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    const RECORD_OWNER: &str = "# This is private data. Do not parse.\nIS_SEAT0=1\nCAN_MULTI_SESSION=1\n\
        CAN_TTY=1\nCAN_GRAPHICAL=1\nACTIVE=2\nACTIVE_UID=1000\nSESSIONS=2 5\nUIDS=1000 1001\n";
    const RECORD_OTHER: &str = "# This is private data. Do not parse.\nIS_SEAT0=1\nCAN_MULTI_SESSION=1\n\
        CAN_TTY=1\nCAN_GRAPHICAL=1\nACTIVE=5\nACTIVE_UID=1001\nSESSIONS=2 5\nUIDS=1000 1001\n";
    /// What a runner without a desktop has: a seat with no active session.
    const RECORD_NOBODY: &str = "# This is private data. Do not parse.\nIS_SEAT0=1\nCAN_MULTI_SESSION=1\n\
        CAN_TTY=1\nCAN_GRAPHICAL=0\n";

    fn owner() -> Active {
        Active::Session {
            id: "2".into(),
            uid: 1000,
        }
    }

    fn other() -> Active {
        Active::Session {
            id: "5".into(),
            uid: 1001,
        }
    }

    struct Fixture {
        dir: TempDir,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let dir = TempDir::new(label);
            for sub in ["seats", "sys", "udev"] {
                fs::create_dir_all(dir.path().join(sub)).unwrap();
            }
            Self { dir }
        }

        fn paths(&self) -> Paths {
            Paths {
                seats: self.dir.path().join("seats"),
                sys_hidraw: self.dir.path().join("sys"),
                udev_data: self.dir.path().join("udev"),
                recheck: Duration::ZERO,
            }
        }

        fn watch(&self) -> SeatWatch {
            SeatWatch::at(self.paths(), "pqkey-42")
        }

        /// A watch of `seat` rather than seat0, as once udev has put the
        /// device there.
        fn watch_on(&self, seat: &str) -> SeatWatch {
            let mut watch = self.watch();
            watch.seat = seat.to_owned();
            watch
        }

        /// Save `seat`'s record as logind 257 and older do: a new file
        /// renamed into place.
        fn save(&self, seat: &str, contents: &str) {
            let seats = self.dir.path().join("seats");
            let temporary = seats.join(format!(".#{seat}tmp"));
            fs::write(&temporary, contents).unwrap();
            fs::rename(&temporary, seats.join(seat)).unwrap();
        }

        /// A hidraw node of the device `uniq`, with the numbers `dev`.
        fn node(&self, name: &str, uniq: &str, dev: &str) {
            let node = self.dir.path().join("sys").join(name);
            fs::create_dir_all(node.join("device")).unwrap();
            fs::write(
                node.join("device").join("uevent"),
                format!("HID_ID=0003:00001209:00000001\nHID_UNIQ={uniq}\n"),
            )
            .unwrap();
            fs::write(node.join("dev"), format!("{dev}\n")).unwrap();
        }

        /// udev's record of the device with the numbers `dev`.
        fn udev_record(&self, dev: &str, contents: &str) {
            fs::write(
                self.dir.path().join("udev").join(format!("c{dev}")),
                contents,
            )
            .unwrap();
        }
    }

    /// The record's active session, as sd_seat_get_active reads it.
    #[test]
    fn the_record_names_the_active_session_and_its_user() {
        assert_eq!(parse_active(RECORD_OWNER), owner());
        assert_eq!(parse_active(RECORD_OTHER), other());
        assert_eq!(parse_active(RECORD_NOBODY), Active::Nobody);
        assert_eq!(parse_active(""), Active::Nobody);
        assert_eq!(
            parse_active("ACTIVE=c1\nACTIVE_UID=120\n"),
            Active::Session {
                id: "c1".into(),
                uid: 120
            }
        );
        // The last value counts, as in parse_env_file.
        assert_eq!(
            parse_active("ACTIVE=2\nACTIVE_UID=1000\nACTIVE=5\nACTIVE_UID=1001\n"),
            other()
        );
        // Comments and whitespace are no keys.
        assert_eq!(
            parse_active("# ACTIVE_UID=1000\n; ACTIVE=2\n"),
            Active::Nobody
        );
        assert_eq!(parse_active("  ACTIVE = 2 \n ACTIVE_UID= 1000\n"), owner());
        // Not what logind writes: the key does not guess, and keeps its
        // device unplugged instead. A quoted value is one of them, though
        // parse_env_file would unquote it.
        for record in [
            "ACTIVE=2\n",
            "ACTIVE_UID=1000\n",
            "ACTIVE=2\nACTIVE_UID=\n",
            "ACTIVE=2\nACTIVE_UID=01000\n",
            "ACTIVE=2\nACTIVE_UID=+1000\n",
            "ACTIVE=2\nACTIVE_UID=-1\n",
            "ACTIVE=2\nACTIVE_UID=4294967295\n",
            "ACTIVE=2\nACTIVE_UID=65535\n",
            "ACTIVE=2\nACTIVE_UID=4294967296\n",
            "ACTIVE=2\nACTIVE_UID=\"1000\"\n",
        ] {
            assert_eq!(parse_active(record), Active::Unknown, "{record:?}");
        }
        assert_eq!(
            parse_active("ACTIVE=1\nACTIVE_UID=0\n"),
            Active::Session {
                id: "1".into(),
                uid: 0
            }
        );
    }

    fn absent(look: &Look) -> bool {
        look.active == Active::Nobody && matches!(look.record, Record::Absent(_))
    }

    fn file(look: &Look) -> bool {
        matches!(look.record, Record::File { .. })
    }

    /// The record that `watch` keeps open since its last look, which no
    /// later record can share an inode number with while it is open.
    fn held(watch: &SeatWatch) -> Option<Record> {
        watch.read.as_ref().map(|file| {
            let metadata = file.metadata().unwrap();
            Record::File {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        })
    }

    /// Whether `look` failed because a record the watch had seen is gone.
    fn gone_since_seen(look: io::Result<Look>) -> bool {
        look.is_err_and(|err| {
            err.kind() == io::ErrorKind::NotFound
                && err.to_string().contains("has gone since the key saw it")
        })
    }

    /// Without the seats directory logind does not run, and nobody is
    /// active; nothing changes until the directory appears.
    #[test]
    fn without_logind_nobody_is_active() {
        let fixture = Fixture::new("seat-absent");
        let seats = fixture.dir.path().join("seats");
        fs::remove_dir(&seats).unwrap();
        let mut watch = fixture.watch();
        assert!(matches!(watch.watch, Watch::Absent(_)));
        let before = watch.look().unwrap();
        assert!(absent(&before));
        assert!(!watch.changed(true).unwrap());
        assert_eq!(watch.look().unwrap(), before);

        // logind starts without a record of this seat, or systemd-tmpfiles
        // makes the directory without logind: what happened before is not
        // known, so this absence is another one.
        fs::create_dir(&seats).unwrap();
        assert!(watch.changed(false).unwrap());
        let started = watch.look().unwrap();
        assert!(absent(&started));
        assert_ne!(started.record, before.record);
        assert!(matches!(watch.watch, Watch::Notified(_)));

        fixture.save("seat0", RECORD_OWNER);
        assert!(watch.changed(false).unwrap());
        let look = watch.look().unwrap();
        assert_eq!(look.active, owner());
        assert!(file(&look));
        assert!(!watch.changed(false).unwrap());
    }

    /// Every save of the record is a file of its own, even with the same
    /// contents; other files in the directory wake the key but leave the
    /// record as it was; one created in place is a file too. A record the key
    /// has not seen is an absence; one it has seen is, once it goes, a record
    /// it cannot read.
    #[test]
    fn every_save_is_a_new_record() {
        let fixture = Fixture::new("seat-records");
        let seats = fixture.dir.path().join("seats");
        let mut watch = fixture.watch();
        assert!(matches!(watch.watch, Watch::Notified(_)));
        let none = watch.look().unwrap();
        assert!(absent(&none));
        assert!(!watch.changed(false).unwrap());

        assert_eq!(held(&watch), None);

        fixture.save("seat0", RECORD_NOBODY);
        assert!(watch.changed(false).unwrap());
        let first = watch.look().unwrap();
        assert_eq!(first.active, Active::Nobody);
        assert!(file(&first));
        assert_eq!(held(&watch), Some(first.record));
        assert!(!watch.changed(false).unwrap());
        // Read again without a change: the same file.
        assert_eq!(watch.look().unwrap(), first);

        fixture.save("seat0", RECORD_NOBODY);
        assert!(watch.changed(true).unwrap());
        let again = watch.look().unwrap();
        assert_eq!(again.active, Active::Nobody);
        assert!(file(&again));
        assert_ne!(again.record, first.record);
        assert_eq!(held(&watch), Some(again.record));
        assert!(!watch.changed(true).unwrap());

        fixture.save("seat1", RECORD_OTHER);
        assert!(watch.changed(false).unwrap());
        assert_eq!(watch.look().unwrap(), again);

        // A record deleted, as logind 257 and older delete it when they
        // fail to save it, or as a seat that goes away.
        fs::remove_file(seats.join("seat0")).unwrap();
        assert!(watch.changed(false).unwrap());
        assert!(gone_since_seen(watch.look()));
        // A record that came and went between two looks.
        fixture.save("seat0", RECORD_OTHER);
        fs::remove_file(seats.join("seat0")).unwrap();
        assert!(watch.changed(false).unwrap());
        assert!(gone_since_seen(watch.look()));

        // Created in place, as logind 258 and later link a seat's first
        // record.
        fs::write(seats.join("seat0"), RECORD_OTHER).unwrap();
        assert!(watch.changed(false).unwrap());
        let created = watch.look().unwrap();
        assert_eq!(created.active, other());
        assert!(file(&created));
    }

    /// Every seat follows the same rule: while the key has seen no record of
    /// a seat other than seat0, a missing one is an absence, which other
    /// files, seat0's record among them, leave as it was; once it has seen
    /// one, a missing one is a record it cannot read.
    #[test]
    fn another_seat_follows_the_same_rule() {
        let fixture = Fixture::new("seat-records-elsewhere");
        let seats = fixture.dir.path().join("seats");
        let mut watch = fixture.watch_on("seat1");
        let none = watch.look().unwrap();
        assert!(absent(&none));
        assert!(!watch.changed(false).unwrap());
        assert_eq!(held(&watch), None);
        fs::write(seats.join(".#seat1tmp"), RECORD_OTHER).unwrap();
        fs::remove_file(seats.join(".#seat1tmp")).unwrap();
        fixture.save("seat0", RECORD_OWNER);
        assert!(watch.changed(false).unwrap());
        assert_eq!(watch.look().unwrap(), none);

        fixture.save("seat1", RECORD_OTHER);
        assert!(watch.changed(false).unwrap());
        let first = watch.look().unwrap();
        assert_eq!(first.active, other());
        assert!(file(&first));
        assert_eq!(held(&watch), Some(first.record));

        // A record deleted, as when its seat goes away.
        fs::remove_file(seats.join("seat1")).unwrap();
        assert!(watch.changed(false).unwrap());
        assert!(gone_since_seen(watch.look()));
        // And another seat's watch still has seen nothing.
        let mut elsewhere = fixture.watch_on("seat2");
        assert!(absent(&elsewhere.look().unwrap()));
    }

    /// A record that came and went before the key read it was named in a
    /// notification, so the key has seen it: once it is gone, the key cannot
    /// tell who is active. Without inotify the key cannot see it, and the
    /// absence stays as it was.
    #[test]
    fn a_record_that_came_and_went_unread_counts_as_seen() {
        let fixture = Fixture::new("seat-unread");
        let seats = fixture.dir.path().join("seats");
        let mut watch = fixture.watch();
        assert!(absent(&watch.look().unwrap()));
        fixture.save("seat0", RECORD_OTHER);
        fs::remove_file(seats.join("seat0")).unwrap();
        assert!(watch.changed(false).unwrap());
        assert!(gone_since_seen(watch.look()));

        let mut polled = fixture.watch_on("seat1");
        polled.watch = Watch::Polled;
        let before = polled.look().unwrap();
        assert!(absent(&before));
        fixture.save("seat1", RECORD_OTHER);
        fs::remove_file(seats.join("seat1")).unwrap();
        assert_eq!(polled.look().unwrap(), before);
    }

    /// Without inotify the key has seen a record once it has read it: once
    /// that record goes, the key cannot tell who is active, as with inotify.
    #[test]
    fn a_record_read_without_inotify_counts_as_seen() {
        let fixture = Fixture::new("seat-polled-seen");
        fixture.save("seat0", RECORD_OWNER);
        let mut watch = fixture.watch();
        watch.watch = Watch::Polled;
        assert!(file(&watch.look().unwrap()));
        fs::remove_file(fixture.dir.path().join("seats").join("seat0")).unwrap();
        assert!(gone_since_seen(watch.look()));
    }

    /// A switch to another user and back between two looks reads the owner
    /// again, from another file.
    #[test]
    fn a_switch_away_and_back_between_two_looks_leaves_another_record() {
        let fixture = Fixture::new("seat-away");
        fixture.save("seat0", RECORD_OWNER);
        let mut watch = fixture.watch();
        let first = watch.look().unwrap();
        assert_eq!(first.active, owner());

        fixture.save("seat0", RECORD_OTHER);
        fixture.save("seat0", RECORD_OWNER);
        assert!(watch.changed(false).unwrap());
        let back = watch.look().unwrap();
        assert_eq!(back.active, owner());
        assert_ne!(back.record, first.record);
    }

    /// Without inotify the key reads the record at every check, and tells
    /// records apart the same way.
    #[test]
    fn the_polled_fallback_tells_records_apart_too() {
        let fixture = Fixture::new("seat-polled");
        fixture.save("seat0", RECORD_OWNER);
        let mut watch = fixture.watch();
        watch.watch = Watch::Polled;
        let first = watch.look().unwrap();
        assert_eq!(first.active, owner());
        assert!(watch.changed(false).unwrap());
        assert_eq!(watch.look().unwrap(), first);

        fixture.save("seat0", RECORD_OTHER);
        fixture.save("seat0", RECORD_OWNER);
        let back = watch.look().unwrap();
        assert_eq!(back.active, owner());
        assert_ne!(back.record, first.record);
    }

    /// Events lost to a full inotify queue may have named the record, so an
    /// absence after them, on a seat other than seat0, is another one;
    /// events that name other files do not change an absence.
    #[test]
    fn lost_events_make_another_absence() {
        let limit = fs::read_to_string("/proc/sys/fs/inotify/max_queued_events")
            .ok()
            .and_then(|limit| limit.trim().parse::<usize>().ok())
            .unwrap_or(16_384);
        if limit > 100_000 {
            eprintln!("skipped: an inotify queue of {limit} events takes too long to fill");
            return;
        }
        let fixture = Fixture::new("seat-overflow");
        let seats = fixture.dir.path().join("seats");
        let mut watch = fixture.watch_on("seat1");
        let before = watch.look().unwrap();
        assert!(absent(&before));
        let churn = |count: usize| {
            for index in 0..count {
                let path = seats.join(format!("x{index}"));
                fs::write(&path, b"").unwrap();
                fs::remove_file(&path).unwrap();
            }
        };
        // Two events each, well within the queue.
        churn(10);
        assert_eq!(watch.look().unwrap(), before);
        // More than the queue holds.
        churn(limit / 2 + 1);
        let after = watch.look().unwrap();
        assert!(absent(&after));
        assert_ne!(after.record, before.record);
    }

    /// A seats directory that is replaced cannot be watched any more: a
    /// record the key had seen is then one it cannot read, and the directory
    /// is watched afresh once it is back.
    #[test]
    fn a_seats_directory_that_goes_away_is_looked_for_again() {
        let fixture = Fixture::new("seat-gone");
        fixture.save("seat0", RECORD_OWNER);
        let mut watch = fixture.watch();
        assert!(file(&watch.look().unwrap()));
        let seats = fixture.dir.path().join("seats");
        fs::rename(&seats, fixture.dir.path().join("old-seats")).unwrap();
        assert!(watch.changed(false).unwrap());
        assert!(gone_since_seen(watch.look()));
        assert!(matches!(watch.watch, Watch::Absent(_)));

        fs::create_dir(&seats).unwrap();
        fixture.save("seat0", RECORD_OTHER);
        assert!(watch.changed(false).unwrap());
        let back = watch.look().unwrap();
        assert_eq!(back.active, other());
        assert!(file(&back));
        assert!(matches!(watch.watch, Watch::Notified(_)));
        fixture.save("seat0", RECORD_OWNER);
        assert!(watch.changed(false).unwrap());
        let next = watch.look().unwrap();
        assert_eq!(next.active, owner());
        assert_ne!(next.record, back.record);
    }

    /// A record the key had seen stays seen when its seats directory goes
    /// away and comes back empty: the key still cannot tell who is active,
    /// and watches the directory afresh.
    #[test]
    fn a_record_seen_is_still_gone_when_its_directory_comes_back_empty() {
        let fixture = Fixture::new("seat-gone-empty");
        fixture.save("seat0", RECORD_OWNER);
        let mut watch = fixture.watch();
        assert!(file(&watch.look().unwrap()));
        let seats = fixture.dir.path().join("seats");
        fs::rename(&seats, fixture.dir.path().join("old-seats")).unwrap();
        assert!(watch.changed(false).unwrap());
        assert!(gone_since_seen(watch.look()));

        fs::create_dir(&seats).unwrap();
        assert!(watch.changed(false).unwrap());
        assert!(gone_since_seen(watch.look()));
        assert!(matches!(watch.watch, Watch::Notified(_)));
    }

    /// The device's seat is the ID_SEAT udev recorded for its node, or
    /// seat0 without one; until udev has recorded the node there is none.
    #[test]
    fn the_device_seat_is_udevs_id_seat() {
        let fixture = Fixture::new("seat-udev");
        let (sys, udev) = (
            fixture.dir.path().join("sys"),
            fixture.dir.path().join("udev"),
        );
        assert_eq!(node_seat(&sys, &udev, "pqkey-42").unwrap(), None);
        fixture.node("hidraw1", "pqkey-41", "241:1");
        fixture.udev_record("241:1", "E:ID_SEAT=seat9\n");
        fixture.node("hidraw2", "pqkey-42", "241:2");
        assert_eq!(node_seat(&sys, &udev, "pqkey-42").unwrap(), None);
        fixture.udev_record(
            "241:2",
            "I:123\nE:ID_PROCESSING=1\nG:uaccess\nQ:uaccess\nV:1\n",
        );
        assert_eq!(
            node_seat(&sys, &udev, "pqkey-42").unwrap().as_deref(),
            Some("seat0")
        );
        fixture.udev_record("241:2", "I:123\nE:ID_SEAT=\nG:uaccess\n");
        assert_eq!(
            node_seat(&sys, &udev, "pqkey-42").unwrap().as_deref(),
            Some("seat0")
        );
        fixture.udev_record("241:2", "I:123\nE:ID_SEAT=seat1\nG:uaccess\nG:seat1\n");
        assert_eq!(
            node_seat(&sys, &udev, "pqkey-42").unwrap().as_deref(),
            Some("seat1")
        );
        assert_eq!(
            node_seat(&fixture.dir.path().join("none"), &udev, "pqkey-42").unwrap(),
            None
        );
        // A device without a unique identifier is not looked for: others
        // have none either.
        fixture.node("hidraw4", "", "241:4");
        fixture.udev_record("241:4", "E:ID_SEAT=seat4\n");
        assert_eq!(node_seat(&sys, &udev, "").unwrap(), None);
    }

    /// A device udev put on another seat moves the watch there, whose record
    /// is another one, and so is its absence: what happened on that seat
    /// before the move was not watched. What the watch has seen is kept per
    /// seat.
    #[test]
    fn a_device_on_another_seat_moves_the_watch_there() {
        let fixture = Fixture::new("seat-moved");
        fixture.save("seat0", RECORD_OWNER);
        fixture.save("seat1", RECORD_OTHER);
        let mut watch = fixture.watch();
        let first = watch.look().unwrap();
        assert_eq!(first.active, owner());
        watch.plugged();
        // udev has not recorded the node yet: seat0 still.
        fixture.node("hidraw3", "pqkey-42", "241:3");
        assert!(!watch.changed(true).unwrap());
        fixture.udev_record("241:3", "E:ID_SEAT=seat1\n");
        assert!(watch.changed(true).unwrap());
        assert_eq!(watch.seat(), "seat1");
        let moved = watch.look().unwrap();
        assert_eq!(moved.active, other());
        assert_ne!(moved.record, first.record);
        assert!(!watch.changed(true).unwrap());
        // Found once per device: later records change nothing until the
        // next device is plugged in.
        fixture.udev_record("241:3", "E:ID_SEAT=seat0\n");
        assert!(!watch.changed(true).unwrap());
        assert_eq!(watch.seat(), "seat1");
        watch.plugged();
        assert!(watch.changed(true).unwrap());
        assert_eq!(watch.seat(), "seat0");
        assert_eq!(watch.look().unwrap().active, owner());

        // A move between two seats that have no record is another absence.
        watch.plugged();
        fixture.udev_record("241:3", "E:ID_SEAT=seat2\n");
        assert!(watch.changed(true).unwrap());
        assert_eq!(watch.seat(), "seat2");
        let before = watch.look().unwrap();
        assert!(absent(&before));
        watch.plugged();
        fixture.udev_record("241:3", "E:ID_SEAT=seat3\n");
        assert!(watch.changed(true).unwrap());
        assert_eq!(watch.seat(), "seat3");
        let after = watch.look().unwrap();
        assert!(absent(&after));
        assert_ne!(after.record, before.record);

        // Back on seat1, whose record the watch has seen, a missing record is
        // one it cannot read.
        fs::remove_file(fixture.dir.path().join("seats").join("seat1")).unwrap();
        watch.plugged();
        fixture.udev_record("241:3", "E:ID_SEAT=seat1\n");
        assert!(watch.changed(true).unwrap());
        assert_eq!(watch.seat(), "seat1");
        assert!(gone_since_seen(watch.look()));
    }

    /// The key says at start how it follows the seat: by watching logind's
    /// records, or not at all, without logind.
    #[test]
    fn the_start_up_log_names_the_mode() {
        use crate::test_support::logs;
        logs::install();
        let fixture = Fixture::new("seat-log");
        let seats = fixture.dir.path().join("seats").display().to_string();
        fixture.watch();
        let logged = logs::containing(&seats);
        assert!(
            logged
                .iter()
                .any(|(level, message)| *level == log::Level::Info
                    && message.starts_with(&format!("watching {seats} for the session"))),
            "{logged:?}"
        );

        let fixture = Fixture::new("seat-log-absent");
        let seats = fixture.dir.path().join("seats");
        fs::remove_dir(&seats).unwrap();
        fixture.watch();
        let logged = logs::containing(&seats.display().to_string());
        assert!(
            logged
                .iter()
                .any(|(level, message)| *level == log::Level::Info
                    && message.contains("does not exist, so logind does not run")
                    && message.ends_with("the key keeps it")),
            "{logged:?}"
        );
    }

    /// The command line asks whether logind's record of seat0 may hold the
    /// device back, to say why a running key has none: another user's
    /// session, a greeter's included; a record the key cannot read or
    /// understand; or a missing one where the seats directory exists, which
    /// holds it back if the key saw the record before, as the command line
    /// cannot tell. Without the directory nothing holds it back.
    #[test]
    fn another_users_session_on_the_seat_is_told_apart_from_yours() {
        let fixture = Fixture::new("seat-cli");
        let seats = fixture.dir.path().join("seats");
        // An empty directory: logind's, once seat0's record has gone, or the
        // one systemd-tmpfiles makes where logind does not run, which the
        // command line cannot tell apart.
        assert_eq!(held_in(&seats, 1000), Some(Held::Missing));
        for (contents, why) in [
            (RECORD_OWNER, None),
            (RECORD_NOBODY, None),
            (RECORD_OTHER, Some(Held::ByAnotherUser)),
            ("ACTIVE=c1\nACTIVE_UID=120\n", Some(Held::ByAnotherUser)),
            ("ACTIVE=2\n", Some(Held::Unreadable)),
        ] {
            fixture.save("seat0", contents);
            assert_eq!(held_in(&seats, 1000), why, "{contents:?}");
        }
        fs::remove_file(seats.join("seat0")).unwrap();
        fs::create_dir(seats.join("seat0")).unwrap();
        assert_eq!(held_in(&seats, 1000), Some(Held::Unreadable), "unreadable");
        fs::remove_dir(seats.join("seat0")).unwrap();
        assert_eq!(held_in(&seats, 1000), Some(Held::Missing));
        fs::remove_dir(&seats).unwrap();
        assert_eq!(held_in(&seats, 1000), None);
    }

    #[test]
    fn a_seat_name_that_is_no_file_name_has_nobody_active() {
        for name in ["", ".", "..", "../seat0", "a/b", "nul\0"] {
            assert!(!is_file_name(name), "{name:?}");
        }
        assert!(is_file_name("seat0") && is_file_name("seat-usb-pci-0000"));
        let fixture = Fixture::new("seat-name");
        fixture.save("seat0", RECORD_OTHER);
        let mut watch = fixture.watch();
        watch.seat = "..".into();
        assert!(absent(&watch.look().unwrap()));
    }

    /// While another thread saves the record over and over, as a switch
    /// away and back would, two looks that read different contents never
    /// report the same file, a look that missed states reports another
    /// file, and the watch never says nothing changed after a save that has
    /// returned.
    #[test]
    fn looks_racing_saves_tell_every_new_record_apart() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        };
        const PAIRS: u64 = 2_000;
        let fixture = Fixture::new("seat-race");
        let seats = fixture.dir.path().join("seats");
        let save = move |seats: &Path, state: u64| {
            let uid = if state % 2 == 1 { 1001 } else { 1000 };
            let temporary = seats.join(".#seat0tmp");
            fs::write(&temporary, format!("ACTIVE={state}\nACTIVE_UID={uid}\n")).unwrap();
            fs::rename(&temporary, seats.join("seat0")).unwrap();
        };
        save(&seats, 0);
        let mut watch = fixture.watch();
        let state = |look: &Look| match &look.active {
            Active::Session { id, .. } => id.parse::<u64>().unwrap(),
            other => panic!("{other:?}"),
        };
        let mut last = watch.look().unwrap();
        let (done, saved) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        );
        let saver = thread::spawn({
            let (done, saved, seats) = (Arc::clone(&done), Arc::clone(&saved), seats.clone());
            move || {
                for pair in 0..PAIRS {
                    for state in [2 * pair + 1, 2 * pair + 2] {
                        save(&seats, state);
                        saved.store(state, Ordering::SeqCst);
                    }
                    let until = Instant::now() + Duration::from_micros(100 + pair % 200);
                    while Instant::now() < until {
                        std::hint::spin_loop();
                    }
                }
                done.store(true, Ordering::SeqCst);
            }
        });
        loop {
            let finished = done.load(Ordering::SeqCst);
            let returned = saved.load(Ordering::SeqCst);
            if !watch.changed(false).unwrap() {
                assert!(
                    returned <= state(&last),
                    "state {returned} was saved, but the watch saw no change since state {}",
                    state(&last)
                );
                if finished {
                    break;
                }
                continue;
            }
            let look = watch.look().unwrap();
            let (before, now) = (state(&last), state(&look));
            if now != before {
                assert_ne!(look.record, last.record, "states {before} and {now}");
            }
            last = look;
        }
        saver.join().unwrap();
        assert_eq!(state(&last), 2 * PAIRS);
    }

    /// Waiting ends at a change, or after the timeout.
    #[test]
    fn waiting_ends_at_a_change_or_the_timeout() {
        let fixture = Fixture::new("seat-wait");
        let mut watch = fixture.watch();
        let started = Instant::now();
        watch.wait(Duration::from_millis(50)).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(50));
        let saver = thread::spawn({
            let seats = fixture.dir.path().join("seats");
            move || {
                thread::sleep(Duration::from_millis(50));
                fs::write(seats.join(".#seat0tmp"), RECORD_OTHER).unwrap();
                fs::rename(seats.join(".#seat0tmp"), seats.join("seat0")).unwrap();
            }
        });
        let started = Instant::now();
        watch.wait(Duration::from_secs(20)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        saver.join().unwrap();
        assert!(watch.changed(false).unwrap());
    }

    /// The device a key plugs in over the real watcher serves only under the
    /// record it was created under: a new file with the same contents, a
    /// switch away and back between two looks, a record that goes, one that
    /// cannot be read, and a seats directory replaced without it each
    /// retire it. Other seats' records and other files in the directory
    /// wake the key but leave the device.
    #[test]
    fn the_device_serves_only_under_its_record() {
        use crate::seat::{Seat, is_unplugged};
        use crate::shutdown::ShutdownSignal;
        let fixture = Fixture::new("seat-rule");
        let seats = fixture.dir.path().join("seats");
        fixture.save("seat0", RECORD_OWNER);
        let mut seat = Seat::new(fixture.watch(), 1000);
        let plug = |seat: &mut Seat<SeatWatch>| {
            seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
                .unwrap();
            seat.plugged();
            seat.check(true).unwrap();
            fixture.save("seat1", RECORD_OTHER);
            seat.check(true).unwrap();
            fs::write(seats.join(".#seat0tmp"), RECORD_OTHER).unwrap();
            fs::remove_file(seats.join(".#seat0tmp")).unwrap();
            seat.check(true).unwrap();
        };
        let retired = |seat: &mut Seat<SeatWatch>| is_unplugged(&seat.check(true).unwrap_err());

        plug(&mut seat);
        fixture.save("seat0", RECORD_OWNER);
        assert!(retired(&mut seat), "the same contents in a new file");

        plug(&mut seat);
        fixture.save("seat0", RECORD_OTHER);
        fixture.save("seat0", RECORD_OWNER);
        assert!(retired(&mut seat), "away and back between two looks");

        plug(&mut seat);
        fs::remove_file(seats.join("seat0")).unwrap();
        assert!(retired(&mut seat), "the record went");

        // No device can be plugged in until the record is back.
        fixture.save("seat0", RECORD_OWNER);
        plug(&mut seat);
        fs::remove_file(seats.join("seat0")).unwrap();
        fs::create_dir(seats.join("seat0")).unwrap();
        assert!(retired(&mut seat), "a record that cannot be read");

        fs::remove_dir(seats.join("seat0")).unwrap();
        fixture.save("seat0", RECORD_OWNER);
        plug(&mut seat);
        fs::rename(&seats, fixture.dir.path().join("old-seats")).unwrap();
        fs::create_dir(&seats).unwrap();
        assert!(
            retired(&mut seat),
            "the directory replaced, without the record"
        );
    }

    /// A device can serve while its seat has no record that the key has
    /// seen: no logind, the empty directory systemd-tmpfiles makes at boot,
    /// or a seat that does not exist yet. A record that comes then is a new
    /// one, which retires the device, and counts as seen from then on: once
    /// it goes, no device is plugged in until it is back. This holds on
    /// every seat. A seats directory replaced while the key has seen no
    /// record of its seat retires the device too, as it may have hidden one.
    #[test]
    fn a_record_never_seen_keeps_the_device_and_one_seen_later_counts() {
        use crate::seat::{Seat, is_unplugged};
        use crate::shutdown::{ShutdownSignal, is_shutdown};
        let fixture = Fixture::new("seat-rule-unseen");
        let seats = fixture.dir.path().join("seats");
        let plug = |seat: &mut Seat<SeatWatch>| {
            seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
                .unwrap();
            seat.plugged();
            seat.check(true).unwrap();
            fixture.save("seat9", RECORD_OTHER);
            seat.check(true).unwrap();
            fs::write(seats.join(".#seattmp"), RECORD_OTHER).unwrap();
            fs::remove_file(seats.join(".#seattmp")).unwrap();
            seat.check(true).unwrap();
        };
        let retired = |seat: &mut Seat<SeatWatch>| is_unplugged(&seat.check(true).unwrap_err());

        for name in ["seat0", "seat1"] {
            let mut seat = Seat::new(fixture.watch_on(name), 1000);
            plug(&mut seat);
            fixture.save(name, RECORD_OWNER);
            assert!(retired(&mut seat), "{name}: the record came");

            plug(&mut seat);
            fs::remove_file(seats.join(name)).unwrap();
            assert!(retired(&mut seat), "{name}: the record went");
            let (result, held) = wait_meanwhile(&mut seat, Duration::from_millis(300), || {});
            assert!(
                result.as_ref().is_err_and(is_shutdown),
                "{name}: plugged in without the record: {result:?}"
            );
            assert_eq!(held, 1, "{name}");

            let (result, _) = wait_meanwhile(&mut seat, Duration::from_secs(10), {
                let seats = seats.clone();
                move || {
                    thread::sleep(Duration::from_millis(100));
                    save_in(&seats, name, RECORD_OWNER);
                }
            });
            result.unwrap();
            seat.plugged();
            seat.check(true).unwrap();
        }

        let mut seat = Seat::new(fixture.watch_on("seat2"), 1000);
        plug(&mut seat);
        fs::rename(&seats, fixture.dir.path().join("old-seats")).unwrap();
        fs::create_dir(&seats).unwrap();
        assert!(
            retired(&mut seat),
            "the directory replaced, without a record seen"
        );
    }

    /// Run `seat.wait_for_turn` while `meanwhile` runs on another thread,
    /// and request shutdown once `meanwhile` is done and `patience` has
    /// passed since; returns what the wait returned and how often it ran
    /// `on_hold`.
    fn wait_meanwhile(
        seat: &mut crate::seat::Seat<SeatWatch>,
        patience: Duration,
        meanwhile: impl FnOnce() + Send + 'static,
    ) -> (io::Result<()>, usize) {
        use crate::shutdown::ShutdownSignal;
        use std::sync::mpsc;
        let shutdown = ShutdownSignal::new();
        let stop = shutdown.clone();
        let (done, finished) = mpsc::channel::<()>();
        let helper = thread::spawn(move || {
            meanwhile();
            if finished.recv_timeout(patience) == Err(mpsc::RecvTimeoutError::Timeout) {
                stop.request();
            }
        });
        let mut held = 0;
        let result = seat.wait_for_turn(&shutdown, || {
            held += 1;
            Ok(())
        });
        drop(done);
        helper.join().unwrap();
        (result, held)
    }

    /// Save `seat`'s record in the seats directory `seats` as logind 257 and
    /// older do: a new file renamed into place.
    fn save_in(seats: &Path, seat: &str, contents: &str) {
        let temporary = seats.join(format!(".#{seat}tmp"));
        fs::write(&temporary, contents).unwrap();
        fs::rename(&temporary, seats.join(seat)).unwrap();
    }

    /// A record the key has seen and that then goes is one the key cannot
    /// tell the active session from. logind 257 and older, and elogind,
    /// remove the record when they fail to save it, and still move the seat's
    /// ACLs themselves at each switch, which then leaves nothing in the
    /// directory to see. So the device goes when the record does, stays away
    /// while saves keep failing and when one names another user, and comes
    /// back once one names its user; the key says why once.
    #[test]
    fn a_missing_seat0_record_keeps_the_device_away_until_a_save_succeeds() {
        use crate::seat::{Seat, is_unplugged};
        use crate::shutdown::{ShutdownSignal, is_shutdown};
        use crate::test_support::logs;
        logs::install();
        let fixture = Fixture::new("seat-failed-save");
        let seats = fixture.dir.path().join("seats");
        fixture.save("seat0", RECORD_OWNER);
        let mut seat = Seat::new(fixture.watch(), 1000);
        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat.check(true).unwrap();

        // A save that fails as logind 257 and older fail one: a temporary
        // file is created and removed, then the record is unlinked.
        let fail_save = {
            let seats = seats.clone();
            move || {
                let temporary = seats.join(".#seat0f41l3d");
                fs::write(&temporary, RECORD_OTHER).unwrap();
                fs::remove_file(&temporary).unwrap();
                match fs::remove_file(seats.join("seat0")) {
                    Err(err) if err.kind() != io::ErrorKind::NotFound => panic!("{err}"),
                    _ => {}
                }
            }
        };
        fail_save();
        assert!(is_unplugged(&seat.check(true).unwrap_err()));

        // The saves of the switches that follow fail too.
        let (result, held) = wait_meanwhile(&mut seat, Duration::from_millis(300), {
            let fail_save = fail_save.clone();
            move || {
                for _ in 0..3 {
                    fail_save();
                    thread::sleep(Duration::from_millis(50));
                }
            }
        });
        assert!(
            result.as_ref().is_err_and(is_shutdown),
            "plugged in without a record: {result:?}"
        );
        assert_eq!(held, 1);

        // A save that names another user keeps the device away too.
        let (result, _) = wait_meanwhile(&mut seat, Duration::from_millis(300), {
            let seats = seats.clone();
            move || save_in(&seats, "seat0", RECORD_OTHER)
        });
        assert!(result.as_ref().is_err_and(is_shutdown), "{result:?}");

        // One that names the owner brings it back, under that record.
        let (result, _) = wait_meanwhile(&mut seat, Duration::from_secs(10), {
            let seats = seats.clone();
            move || {
                thread::sleep(Duration::from_millis(100));
                save_in(&seats, "seat0", RECORD_OWNER);
            }
        });
        result.unwrap();
        seat.plugged();
        seat.check(true).unwrap();
        fixture.save("seat1", RECORD_OTHER);
        seat.check(true).unwrap();

        let record = seats.join("seat0").display().to_string();
        let warned = logs::containing(&format!("({record} has gone since the key saw it"));
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert_eq!(warned[0].0, log::Level::Warn);
        assert!(
            warned[0]
                .1
                .starts_with("cannot tell whose session is active on seat0 ("),
            "{warned:?}"
        );
    }

    /// A record gone since the key saw it is read again after every wait,
    /// with no change in the seats directory to wake the key: here the
    /// record is a symbolic link to a file outside it, which goes away and
    /// comes back.
    #[test]
    fn a_record_gone_since_it_was_seen_is_read_again_until_it_is_back() {
        use crate::seat::{Seat, is_unplugged};
        use crate::shutdown::ShutdownSignal;
        let fixture = Fixture::new("seat-missing-again");
        let seats = fixture.dir.path().join("seats");
        let target = fixture.dir.path().join("target");
        fs::write(&target, RECORD_OWNER).unwrap();
        std::os::unix::fs::symlink(&target, seats.join("seat0")).unwrap();
        let mut seat = Seat::new(fixture.watch(), 1000);
        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat.check(true).unwrap();

        fs::remove_file(&target).unwrap();
        // Something else in the directory wakes the key, which then finds
        // no record.
        fs::write(seats.join(".#seat0tmp"), b"").unwrap();
        assert!(is_unplugged(&seat.check(true).unwrap_err()));
        let (result, held) = wait_meanwhile(&mut seat, Duration::from_secs(10), move || {
            thread::sleep(Duration::from_millis(300));
            fs::write(&target, RECORD_OWNER).unwrap();
        });
        result.unwrap();
        assert_eq!(held, 1);
        seat.plugged();
        seat.check(true).unwrap();
    }

    /// How many of this process's descriptors are open on the file with the
    /// device and inode numbers `dev` and `ino`.
    fn open_files(dev: u64, ino: u64) -> usize {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter_map(|entry| fs::metadata(entry.path()).ok())
            .filter(|metadata| metadata.dev() == dev && metadata.ino() == ino)
            .count()
    }

    /// A look keeps the file it read open until the next look has opened
    /// the record, so the old file's inode is not freed before then, and a
    /// filesystem that gives freed numbers again cannot give its number to
    /// the file the next look reads. Here the next record is a FIFO that
    /// the test holds open: the look opens it at once and then waits in its
    /// read until the test writes, and meanwhile the test sees which files
    /// the process has open.
    #[test]
    fn a_look_holds_the_last_record_until_it_has_opened_the_next() {
        use nix::{sys::stat::Mode, unistd::mkfifo};
        use std::io::Write;
        let fixture = Fixture::new("seat-hold");
        let seats = fixture.dir.path().join("seats");
        fixture.save("seat0", RECORD_OWNER);
        let mut watch = fixture.watch();
        let Record::File { dev, ino } = watch.look().unwrap().record else {
            panic!("the record was no file");
        };
        assert_eq!(open_files(dev, ino), 1);

        let fifo = seats.join(".#seat0fifo");
        mkfifo(&fifo, Mode::from_bits_truncate(0o644)).unwrap();
        // Opened to read and write, a FIFO does not wait for the other side.
        let mut writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        fs::rename(&fifo, seats.join("seat0")).unwrap();
        let (fifo_dev, fifo_ino) = {
            let metadata = writer.metadata().unwrap();
            (metadata.dev(), metadata.ino())
        };
        let looker = thread::spawn(move || watch.look());
        let deadline = Instant::now() + Duration::from_secs(10);
        while open_files(fifo_dev, fifo_ino) < 2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let opened = open_files(fifo_dev, fifo_ino) >= 2;
        let still_held = open_files(dev, ino) > 0;
        writer.write_all(RECORD_OTHER.as_bytes()).unwrap();
        drop(writer);
        let look = looker.join().unwrap().unwrap();
        assert!(opened, "the look never opened the record");
        assert!(
            still_held,
            "the last record was released before the next was opened"
        );
        assert_eq!(look.active, other());
        assert_eq!(
            look.record,
            Record::File {
                dev: fifo_dev,
                ino: fifo_ino
            }
        );
    }

    /// A record that cannot be read is read again after every wait, with no
    /// change in the seats directory to wake the key, and the device comes
    /// back once it can be. The record is a symbolic link to a file outside
    /// the directory, which the test replaces with a directory and back.
    #[test]
    fn an_unreadable_record_is_read_again_until_it_can_be_read() {
        use crate::seat::{Seat, is_unplugged};
        use crate::shutdown::{ShutdownSignal, is_shutdown};
        use std::sync::mpsc;
        let fixture = Fixture::new("seat-unreadable");
        let seats = fixture.dir.path().join("seats");
        let target = fixture.dir.path().join("target");
        fs::write(&target, RECORD_OWNER).unwrap();
        std::os::unix::fs::symlink(&target, seats.join("seat0")).unwrap();
        let mut seat = Seat::new(fixture.watch(), 1000);
        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat.check(true).unwrap();

        fs::remove_file(&target).unwrap();
        fs::create_dir(&target).unwrap();
        // Something else in the directory wakes the key, which then cannot
        // read the record.
        fs::write(seats.join(".#seat0tmp"), b"").unwrap();
        assert!(is_unplugged(&seat.check(true).unwrap_err()));

        let shutdown = ShutdownSignal::new();
        let stop = shutdown.clone();
        let (done, finished) = mpsc::channel::<()>();
        let restorer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            fs::remove_dir(&target).unwrap();
            fs::write(&target, RECORD_OWNER).unwrap();
            if finished.recv_timeout(Duration::from_secs(10))
                == Err(mpsc::RecvTimeoutError::Timeout)
            {
                stop.request();
            }
        });
        let result = seat.wait_for_turn(&shutdown, || Ok(()));
        drop(done);
        restorer.join().unwrap();
        assert!(
            result.as_ref().is_ok(),
            "still held{}",
            if result.as_ref().is_err_and(is_shutdown) {
                " until shutdown"
            } else {
                ""
            }
        );
        seat.plugged();
        seat.check(true).unwrap();
    }
}
