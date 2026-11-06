//! Whether the key's device may exist: who is active on its seat.
//!
//! udev gives the key's hidraw node to the user whose session logind records
//! as active on the node's seat (the `uaccess` tag), and a file opened on the
//! node keeps working after that moves on. So the key keeps a device only
//! while the seat's active session is one of its own user's, or no session is
//! active there, when udev gives the node to nobody.
//!
//! logind writes each state of a seat to a new file, which it renames, or
//! for a seat's first record may link, into place as the seat's record, so
//! the file identifies the state. A device serves only while the record is
//! the file it was created under, or is still absent, for a seat whose
//! record the key has not seen since it started: any other file retires it,
//! even one that names the same session, and so does a record that cannot
//! be read, or that has gone since the key saw it. A switch to another user
//! and back that falls between two looks leaves another file in place, so it
//! retires the device however the looks fall. The cost: the key replaces its device
//! whenever logind saves the record, also when that leaves you active, as
//! when another session on the seat starts or ends.
//!
//! [`Seat`] decides from what a [`SeatSource`] reports. [`SeatDevice`] asks it
//! before the transport handles or sends each report, and fails once the
//! device must go: that ends the transport, which destroys the device and with
//! it every file opened on its node. The daemon then waits until the seat is
//! free and creates a new device, which gets a new node, under the record it
//! saw last.

use std::{cell::RefCell, error::Error, fmt, io, os::fd::BorrowedFd, thread, time::Duration};

use crate::{
    shutdown::ShutdownSignal,
    transport::{CtapHidFrame, HidDevice},
};

/// How long [`Seat::wait_for_turn`] waits for the seat at a time before it
/// looks at the shutdown flag again, and reads a record it could not read
/// again.
const WAIT: Duration = Duration::from_millis(100);

/// Who logind records as active on a seat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Active {
    /// No session is active there, logind knows no such seat, or logind does
    /// not run: udev gives the device to no user.
    Nobody,
    /// The session `id` of the user `uid`.
    Session { id: String, uid: u32 },
    /// The seat's record could not be read or understood, or has gone since
    /// the key saw it, so the active session may be anyone's.
    Unknown,
}

/// Which record of the seat a look read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// There was none, and the key has seen none since it started: a seat
    /// logind does not have, or no logind. The number tells two such looks
    /// apart when something may have come and gone between them.
    Absent(u64),
    /// The file with this device and inode number. logind writes every state
    /// to a new file, so the same file holds the same state.
    File { dev: u64, ino: u64 },
}

/// What one look at the seat found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Look {
    pub active: Active,
    pub record: Record,
}

/// Where looks come from: logind's records on Linux, a script in tests.
pub trait SeatSource {
    /// The seat's name, for messages.
    fn seat(&self) -> &str;
    /// Whether the record may have been replaced since the last look. It is
    /// asked before every report the device handles or sends, so it must be
    /// cheap; a `false` must be certain. `report` says a report has just
    /// arrived.
    fn changed(&mut self, report: bool) -> io::Result<bool>;
    /// Look at the seat now: read its record, and say which one it was.
    fn look(&mut self) -> io::Result<Look>;
    /// Wait until the record may have been replaced, or `timeout` passes.
    fn wait(&mut self, timeout: Duration) -> io::Result<()>;
    /// A new device has been created.
    fn plugged(&mut self) {}
}

/// A seat without a record that no session is ever active on, so the device
/// always stays: for a single device served until it fails or shutdown is
/// requested.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unwatched;

impl SeatSource for Unwatched {
    fn seat(&self) -> &str {
        "the seat"
    }

    fn changed(&mut self, _report: bool) -> io::Result<bool> {
        Ok(false)
    }

    fn look(&mut self) -> io::Result<Look> {
        Ok(Look {
            active: Active::Nobody,
            record: Record::Absent(0),
        })
    }

    fn wait(&mut self, timeout: Duration) -> io::Result<()> {
        thread::sleep(timeout);
        Ok(())
    }
}

/// Decides, from looks at its source, when the device of a key that runs as
/// the user `owner` may exist.
pub struct Seat<S> {
    source: S,
    owner: u32,
    /// Who the last look found active, `Unknown` if it could not read the
    /// record; `None` before the first look.
    active: Option<Active>,
    /// The record the last look read, if it could read one.
    record: Option<Record>,
    /// The record the device that exists was created under.
    under: Option<Record>,
    /// Whether that device must go.
    retired: bool,
    /// Whether the log last said the device is unplugged until the seat is
    /// free.
    held: bool,
}

impl<S: SeatSource> Seat<S> {
    pub fn new(source: S, owner: u32) -> Self {
        Self {
            source,
            owner,
            active: None,
            record: None,
            under: None,
            retired: false,
            held: false,
        }
    }

    /// Whether `active` lets the key's device exist.
    fn allows(&self, active: &Active) -> bool {
        match active {
            Active::Nobody => true,
            Active::Session { uid, .. } => *uid == self.owner,
            Active::Unknown => false,
        }
    }

    /// Whether the last look lets a device exist.
    fn allowed(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| self.allows(active))
    }

    /// Whether the record may have been replaced; an error counts as a
    /// replacement.
    fn changed(&mut self, report: bool) -> bool {
        self.source.changed(report).unwrap_or_else(|err| {
            log::debug!("cannot tell whether {} changed ({err})", self.source.seat());
            true
        })
    }

    /// Look at the seat and remember what it found. A failed look is a
    /// state the key cannot tell apart from another user's. Such a state is
    /// logged when it follows one the key could tell.
    fn look(&mut self) {
        let (active, record, error) = match self.source.look() {
            Ok(look) => (look.active, Some(look.record), None),
            Err(err) => (Active::Unknown, None, Some(err)),
        };
        let seat = self.source.seat();
        match &active {
            Active::Unknown if self.active != Some(Active::Unknown) => {
                let reason = error.map_or_else(
                    || "its record names an active session without a valid user".to_owned(),
                    |err| err.to_string(),
                );
                log::warn!(
                    "cannot tell whose session is active on {seat} ({reason}): the key keeps its \
                     device unplugged until it can"
                );
                self.held = true;
            }
            Active::Session { id, uid } if self.active.as_ref() != Some(&active) => {
                log::debug!("session {id} of uid {uid} is active on {seat}");
            }
            _ => {}
        }
        self.active = Some(active);
        self.record = record;
    }

    /// What the last look found, in words: who is active.
    fn who(&self) -> &'static str {
        match self.active {
            Some(Active::Session { uid, .. }) if uid == self.owner => "your session is",
            Some(Active::Session { .. }) => "another user's session is",
            Some(Active::Unknown) => "an unknown session may be",
            Some(Active::Nobody) | None => "no session is",
        }
    }

    /// Wait until a device may exist: until the seat's active session is one
    /// of this user's, or none, or shutdown is requested, which ends with
    /// [`shutdown_error`](crate::shutdown::shutdown_error). If the device has
    /// to wait, `on_hold` runs once, before the wait.
    pub fn wait_for_turn(
        &mut self,
        shutdown: &ShutdownSignal,
        mut on_hold: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.active.is_none() || self.changed(false) {
            self.look();
        }
        let mut waited = false;
        loop {
            if self.allowed() {
                if self.held {
                    log::info!(
                        "{} active on {}: the key plugs its device in again",
                        self.who(),
                        self.source.seat()
                    );
                    self.held = false;
                }
                return Ok(());
            }
            if !self.held {
                log::info!(
                    "{} active on {}: the key keeps its device unplugged until yours, or none, is",
                    self.who(),
                    self.source.seat()
                );
                self.held = true;
            }
            if !waited {
                on_hold()?;
                waited = true;
            }
            shutdown.check()?;
            self.source.wait(WAIT)?;
            // A record that could not be read is read again after every
            // wait: nothing in the seats directory need change for it to
            // become readable again.
            if self.changed(false) || self.active == Some(Active::Unknown) {
                self.look();
            }
        }
    }

    /// A device has been created, under the record the last look read; it
    /// may serve until [`Self::check`] says otherwise.
    pub fn plugged(&mut self) {
        self.under = self.record;
        self.retired = false;
        self.source.plugged();
    }

    /// Whether the device may go on serving: `Ok(())` if so, and
    /// [`unplugged`] once it must go, which it must when the seat's record
    /// is no longer the one it was created under. `report` says a report has
    /// just arrived, which is handled only if this returns `Ok(())`.
    pub fn check(&mut self, report: bool) -> io::Result<()> {
        if !self.retired && self.changed(report) {
            self.look();
            if !self.allowed() {
                self.retired = true;
                if !self.held {
                    log::info!(
                        "{} active on {}: removing the key's device until yours, or none, is",
                        self.who(),
                        self.source.seat()
                    );
                    self.held = true;
                }
            } else if self.record != self.under {
                self.retired = true;
                log::info!(
                    "logind rewrote {}'s record: replacing the key's device, in case another \
                     user's session was active since it was created",
                    self.source.seat()
                );
            }
        }
        if self.retired {
            Err(unplugged())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct Unplugged;

impl fmt::Display for Unplugged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the device was unplugged: another user's session may be active on its seat")
    }
}

impl Error for Unplugged {}

/// The error with which a [`SeatDevice`] ends the transport.
pub fn unplugged() -> io::Error {
    io::Error::other(Unplugged)
}

/// Whether `err` is [`unplugged`].
pub fn is_unplugged(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|inner| inner.is::<Unplugged>())
}

/// A device that asks `seat` before each report it hands the transport and
/// before each one it sends, and fails with [`unplugged`] once the device
/// must go. The report is then neither handled nor sent, and the transport
/// ends, dropping the device, which destroys it.
pub struct SeatDevice<'seat, D, S> {
    device: D,
    seat: &'seat RefCell<Seat<S>>,
}

impl<'seat, D, S> SeatDevice<'seat, D, S> {
    pub fn new(device: D, seat: &'seat RefCell<Seat<S>>) -> Self {
        Self { device, seat }
    }
}

impl<D: HidDevice, S: SeatSource> HidDevice for SeatDevice<'_, D, S> {
    fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>> {
        let frame = self.device.try_read_frame()?;
        self.seat.borrow_mut().check(frame.is_some())?;
        Ok(frame)
    }

    fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()> {
        self.seat.borrow_mut().check(false)?;
        self.device.write_frame(frame)
    }

    fn wait_with(&self, other: BorrowedFd<'_>, timeout: Option<Duration>) -> io::Result<bool> {
        self.device.wait_with(other, timeout)
    }
}

/// A seat a test switches between sessions.
#[cfg(test)]
pub(crate) mod scripted {
    use std::sync::{Arc, Condvar, Mutex, MutexGuard};

    use super::*;

    struct State {
        active: Active,
        /// Whether the seat has a record.
        present: bool,
        /// How many records have been written or removed, and how many of
        /// them the key had seen at its last look. Each write is a new file.
        recorded: u64,
        seen: u64,
        looks: usize,
        /// States to record when the next report arrives.
        at_next_report: Vec<Active>,
    }

    impl State {
        fn record(&mut self, states: &[Active]) {
            for active in states {
                self.active = active.clone();
                self.present = true;
                self.recorded += 1;
            }
        }

        fn look(&self) -> Look {
            let record = if self.present {
                Record::File {
                    dev: 0,
                    ino: self.recorded,
                }
            } else {
                Record::Absent(self.recorded)
            };
            Look {
                active: self.active.clone(),
                record,
            }
        }
    }

    struct Script {
        name: String,
        state: Mutex<State>,
        recorded: Condvar,
    }

    /// A seat whose records a test writes, as logind would. Clones share
    /// the seat.
    #[derive(Clone)]
    pub(crate) struct ScriptedSeat(Arc<Script>);

    impl ScriptedSeat {
        /// seat0, whose record names `active` as active.
        pub(crate) fn new(active: Active) -> Self {
            Self::named("seat0", active)
        }

        pub(crate) fn named(name: &str, active: Active) -> Self {
            Self(Arc::new(Script {
                name: name.to_owned(),
                state: Mutex::new(State {
                    active,
                    present: true,
                    recorded: 1,
                    seen: 0,
                    looks: 0,
                    at_next_report: Vec::new(),
                }),
                recorded: Condvar::new(),
            }))
        }

        /// seat0 without a record.
        pub(crate) fn absent() -> Self {
            let seat = Self::new(Active::Nobody);
            seat.state().present = false;
            seat
        }

        fn state(&self) -> MutexGuard<'_, State> {
            self.0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        /// Write a record naming each of `states` in turn, with no look in
        /// between.
        pub(crate) fn switch(&self, states: &[Active]) {
            self.state().record(states);
            self.0.recorded.notify_all();
        }

        /// Remove the record, as logind does when the seat goes away.
        pub(crate) fn remove(&self) {
            let mut state = self.state();
            state.active = Active::Nobody;
            state.present = false;
            state.recorded += 1;
            self.0.recorded.notify_all();
        }

        /// Write `states` the moment the next report arrives, before the key
        /// is asked whether the record changed.
        pub(crate) fn switch_at_next_report(&self, states: &[Active]) {
            self.state().at_next_report = states.to_vec();
        }

        /// How many times the key has looked.
        pub(crate) fn looks(&self) -> usize {
            self.state().looks
        }
    }

    impl SeatSource for ScriptedSeat {
        fn seat(&self) -> &str {
            &self.0.name
        }

        fn changed(&mut self, report: bool) -> io::Result<bool> {
            let mut state = self.state();
            if report {
                let states = std::mem::take(&mut state.at_next_report);
                state.record(&states);
            }
            Ok(state.recorded != state.seen)
        }

        fn look(&mut self) -> io::Result<Look> {
            let mut state = self.state();
            state.seen = state.recorded;
            state.looks += 1;
            Ok(state.look())
        }

        fn wait(&mut self, timeout: Duration) -> io::Result<()> {
            let state = self.state();
            drop(
                self.0
                    .recorded
                    .wait_timeout_while(state, timeout, |state| state.recorded == state.seen)
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scripted::ScriptedSeat;
    use super::*;
    use crate::shutdown::is_shutdown;
    use std::{
        cell::Cell,
        rc::Rc,
        sync::mpsc,
        time::{Duration, Instant},
    };

    const OWNER: u32 = 1000;

    fn owner() -> Active {
        Active::Session {
            id: "2".into(),
            uid: OWNER,
        }
    }

    fn other() -> Active {
        Active::Session {
            id: "5".into(),
            uid: 1001,
        }
    }

    /// GDM's login screen runs as a user of its own.
    fn greeter() -> Active {
        Active::Session {
            id: "c1".into(),
            uid: 120,
        }
    }

    /// A seat whose device has just been plugged in.
    fn plugged(script: &ScriptedSeat) -> Seat<ScriptedSeat> {
        let mut seat = Seat::new(script.clone(), OWNER);
        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat
    }

    /// Run `wait_for_turn` until it returns, or until shutdown is requested
    /// after `patience`; returns its result and how often `on_hold` ran.
    fn wait_at_most<S: SeatSource>(
        seat: &mut Seat<S>,
        patience: Duration,
    ) -> (io::Result<()>, usize) {
        let shutdown = ShutdownSignal::new();
        let (done, finished) = mpsc::channel::<()>();
        let stop = shutdown.clone();
        let stopper = thread::spawn(move || {
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
        stopper.join().unwrap();
        (result, held)
    }

    /// A device may exist while the owner's session, or none, is active,
    /// and never while another user's, a greeter's or one the key cannot
    /// tell is: then the key waits, and says it runs.
    #[test]
    fn only_the_owner_or_nobody_lets_a_device_exist() {
        for (active, allowed) in [
            (owner(), true),
            (Active::Nobody, true),
            (other(), false),
            (greeter(), false),
            (Active::Unknown, false),
        ] {
            let mut seat = Seat::new(ScriptedSeat::new(active.clone()), OWNER);
            let (result, held) = wait_at_most(&mut seat, Duration::from_millis(300));
            if allowed {
                assert!(result.is_ok(), "{active:?}");
                assert_eq!(held, 0, "{active:?}");
            } else {
                assert!(is_shutdown(&result.unwrap_err()), "{active:?}");
                assert_eq!(held, 1, "{active:?}");
            }
        }
        let mut seat = Seat::new(ScriptedSeat::absent(), OWNER);
        assert!(
            wait_at_most(&mut seat, Duration::from_millis(300))
                .0
                .is_ok()
        );
    }

    /// The device serves only under the record it was created under: any
    /// new record retires it, whoever it names, the owner included; another
    /// user's session is unplugged until the seat is free again.
    #[test]
    fn any_new_record_retires_the_device() {
        for active in [owner(), Active::Nobody, other(), greeter(), Active::Unknown] {
            let script = ScriptedSeat::new(owner());
            let mut seat = plugged(&script);
            assert!(seat.check(true).is_ok());
            script.switch(std::slice::from_ref(&active));
            assert!(is_unplugged(&seat.check(true).unwrap_err()), "{active:?}");
            // Retired for good: the next report is not handled either.
            assert!(is_unplugged(&seat.check(false).unwrap_err()));
        }
    }

    /// A switch to another user and back that happens between two looks
    /// retires the device, though both looks find the owner active.
    #[test]
    fn a_switch_away_and_back_between_two_looks_retires_the_device() {
        for away in [other(), greeter(), Active::Unknown] {
            let script = ScriptedSeat::new(owner());
            let mut seat = plugged(&script);
            script.switch(&[away, owner()]);
            assert!(is_unplugged(&seat.check(false).unwrap_err()));
            // The seat is the owner's again, so a new device may exist at
            // once, and serves under the new record.
            seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
                .unwrap();
            seat.plugged();
            seat.check(true).unwrap();
        }
    }

    /// A device is created under the record the last look read, not under
    /// one saved while it was being created: a switch to another user, or
    /// away and back, or any other save between the look that let the
    /// device exist and its creation retires it at its first check.
    #[test]
    fn a_save_just_before_the_device_is_created_retires_it() {
        for states in [vec![other()], vec![other(), owner()], vec![owner()]] {
            let script = ScriptedSeat::new(owner());
            let mut seat = Seat::new(script.clone(), OWNER);
            seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
                .unwrap();
            script.switch(&states);
            seat.plugged();
            assert!(is_unplugged(&seat.check(false).unwrap_err()), "{states:?}");
        }
    }

    /// A source that cannot say whether the record was replaced.
    struct Blind {
        look: Rc<RefCell<Look>>,
    }

    impl SeatSource for Blind {
        fn seat(&self) -> &str {
            "seat0"
        }
        fn changed(&mut self, _report: bool) -> io::Result<bool> {
            Err(io::Error::other("poll failed"))
        }
        fn look(&mut self) -> io::Result<Look> {
            Ok(self.look.borrow().clone())
        }
        fn wait(&mut self, timeout: Duration) -> io::Result<()> {
            thread::sleep(timeout);
            Ok(())
        }
    }

    /// When the source cannot say whether the record was replaced, the key
    /// takes it as replaced and looks: another record retires the device.
    #[test]
    fn a_change_the_source_cannot_rule_out_is_looked_at() {
        let look = Rc::new(RefCell::new(Look {
            active: owner(),
            record: Record::File { dev: 0, ino: 1 },
        }));
        let mut seat = Seat::new(
            Blind {
                look: Rc::clone(&look),
            },
            OWNER,
        );
        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat.check(true).unwrap();
        seat.check(false).unwrap();
        look.borrow_mut().record = Record::File { dev: 0, ino: 2 };
        assert!(is_unplugged(&seat.check(false).unwrap_err()));
    }

    /// A record that appears, or goes, retires the device, and so does one
    /// that comes and goes between two looks.
    #[test]
    fn the_record_appearing_or_disappearing_retires_the_device() {
        let script = ScriptedSeat::absent();
        let mut seat = plugged(&script);
        seat.check(true).unwrap();
        script.switch(&[owner()]);
        assert!(is_unplugged(&seat.check(true).unwrap_err()));

        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat.check(true).unwrap();
        script.remove();
        assert!(is_unplugged(&seat.check(true).unwrap_err()));

        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat.check(true).unwrap();
        script.switch(&[other()]);
        script.remove();
        assert!(is_unplugged(&seat.check(true).unwrap_err()));
    }

    /// Nothing is looked at again until the source reports a change, so
    /// checking before every report costs only that question.
    #[test]
    fn the_seat_is_looked_at_only_when_it_may_have_changed() {
        let script = ScriptedSeat::new(owner());
        let mut seat = plugged(&script);
        for _ in 0..100 {
            seat.check(true).unwrap();
        }
        assert_eq!(script.looks(), 1);
        script.switch(&[owner()]);
        assert!(seat.check(false).is_err());
        assert_eq!(script.looks(), 2);
    }

    /// While another user's session is active, the device waits: the hold
    /// is announced, and the wait ends when the owner's session, or none, is
    /// active again, or shutdown is requested.
    #[test]
    fn the_device_waits_while_another_user_is_active() {
        for back in [owner(), Active::Nobody] {
            let script = ScriptedSeat::new(other());
            let switcher = script.clone();
            let back_again = back.clone();
            let releaser = thread::spawn(move || {
                thread::sleep(Duration::from_millis(200));
                // Still someone else's: the wait goes on.
                switcher.switch(&[greeter()]);
                thread::sleep(Duration::from_millis(200));
                switcher.switch(&[back_again]);
            });
            let started = Instant::now();
            let mut seat = Seat::new(script.clone(), OWNER);
            let (result, held) = wait_at_most(&mut seat, Duration::from_secs(20));
            releaser.join().unwrap();
            result.unwrap();
            assert!(started.elapsed() >= Duration::from_millis(400), "{back:?}");
            assert_eq!(held, 1);
            seat.plugged();
            seat.check(true).unwrap();
        }

        let mut seat = Seat::new(ScriptedSeat::new(greeter()), OWNER);
        let (result, held) = wait_at_most(&mut seat, Duration::from_millis(200));
        assert!(is_shutdown(&result.unwrap_err()));
        assert_eq!(held, 1);
    }

    /// A source like the real one: it reports a change only when one is
    /// pending, and a look takes it. Its reads can fail.
    struct Flaky {
        pending: Rc<Cell<bool>>,
        failing: Rc<Cell<bool>>,
        looks: Rc<Cell<usize>>,
    }

    impl SeatSource for Flaky {
        fn seat(&self) -> &str {
            "seat0"
        }
        fn changed(&mut self, _report: bool) -> io::Result<bool> {
            Ok(self.pending.get())
        }
        fn look(&mut self) -> io::Result<Look> {
            self.pending.set(false);
            self.looks.set(self.looks.get() + 1);
            if self.failing.get() {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(Look {
                active: Active::Nobody,
                record: Record::File { dev: 0, ino: 1 },
            })
        }
        fn wait(&mut self, timeout: Duration) -> io::Result<()> {
            thread::sleep(timeout);
            Ok(())
        }
    }

    /// A record that cannot be read retires the device. It is read again
    /// after every wait, though no change is reported after the failed
    /// read, and the device comes back once it can be read.
    #[test]
    fn a_record_that_cannot_be_read_retires_the_device_until_it_can() {
        let pending = Rc::new(Cell::new(true));
        let failing = Rc::new(Cell::new(false));
        let looks = Rc::new(Cell::new(0));
        let mut seat = Seat::new(
            Flaky {
                pending: Rc::clone(&pending),
                failing: Rc::clone(&failing),
                looks: Rc::clone(&looks),
            },
            OWNER,
        );
        seat.wait_for_turn(&ShutdownSignal::new(), || unreachable!())
            .unwrap();
        seat.plugged();
        seat.check(true).unwrap();

        failing.set(true);
        pending.set(true);
        assert!(is_unplugged(&seat.check(true).unwrap_err()));
        assert!(!pending.get());
        let before = looks.get();
        let readable = Rc::clone(&failing);
        let (result, held) = {
            let shutdown = ShutdownSignal::new();
            let stop = shutdown.clone();
            let (done, finished) = mpsc::channel::<()>();
            let stopper = thread::spawn(move || {
                if finished.recv_timeout(Duration::from_secs(5))
                    == Err(mpsc::RecvTimeoutError::Timeout)
                {
                    stop.request();
                }
            });
            let mut held = 0;
            let result = seat.wait_for_turn(&shutdown, || {
                held += 1;
                // Readable again, with no change reported.
                readable.set(false);
                Ok(())
            });
            drop(done);
            stopper.join().unwrap();
            (result, held)
        };
        result.unwrap();
        assert_eq!(held, 1);
        assert_eq!(looks.get(), before + 1, "read again after the first wait");
        seat.plugged();
        seat.check(true).unwrap();
    }

    /// The device refuses a report that arrives once the seat is another
    /// user's, and sends nothing more: the transport sees `unplugged`.
    #[test]
    fn a_seat_device_neither_hands_on_nor_sends_reports_once_retired() {
        let (device, peer) = crate::test_support::callback::pair();
        let script = ScriptedSeat::new(owner());
        let seat = RefCell::new(plugged(&script));
        let device = SeatDevice::new(device, &seat);

        peer.send(&[1; 64]).unwrap();
        assert_eq!(device.try_read_frame().unwrap().unwrap().0, [1; 64]);
        device.write_frame(&CtapHidFrame::new([2; 64])).unwrap();
        assert_eq!(peer.receive(Duration::from_secs(5)).unwrap(), Some([2; 64]));

        script.switch(&[other()]);
        peer.send(&[3; 64]).unwrap();
        assert!(is_unplugged(&device.try_read_frame().unwrap_err()));
        assert!(is_unplugged(
            &device.write_frame(&CtapHidFrame::new([4; 64])).unwrap_err()
        ));
        assert_eq!(peer.receive(Duration::from_millis(100)).unwrap(), None);
    }

    /// Each change of the device's state is logged once, saying why; the
    /// manual check in docs/development-notes.md looks for these lines.
    #[test]
    fn plugging_and_unplugging_are_logged_once_each() {
        use crate::test_support::logs;
        logs::install();
        let script = ScriptedSeat::named("seat-transitions", other());
        let mut seat = Seat::new(script.clone(), OWNER);
        let releaser = thread::spawn({
            let script = script.clone();
            move || {
                thread::sleep(Duration::from_millis(100));
                script.switch(&[greeter()]);
                thread::sleep(Duration::from_millis(100));
                script.switch(&[owner()]);
            }
        });
        seat.wait_for_turn(&ShutdownSignal::new(), || Ok(()))
            .unwrap();
        releaser.join().unwrap();
        seat.plugged();
        script.switch(&[other()]);
        assert!(seat.check(true).is_err());
        assert!(seat.check(false).is_err());
        script.switch(&[Active::Nobody]);
        seat.wait_for_turn(&ShutdownSignal::new(), || Ok(()))
            .unwrap();
        seat.plugged();
        script.switch(&[other(), owner()]);
        assert!(seat.check(false).is_err());

        let logged: Vec<String> = logs::containing("seat-transitions")
            .into_iter()
            .filter(|(level, _)| *level == log::Level::Info)
            .map(|(_, message)| message)
            .collect();
        assert_eq!(
            logged,
            [
                "another user's session is active on seat-transitions: the key keeps its device \
                 unplugged until yours, or none, is",
                "your session is active on seat-transitions: the key plugs its device in again",
                "another user's session is active on seat-transitions: removing the key's device \
                 until yours, or none, is",
                "no session is active on seat-transitions: the key plugs its device in again",
                "logind rewrote seat-transitions's record: replacing the key's device, in case \
                 another user's session was active since it was created",
            ]
        );
    }

    #[test]
    fn only_the_unplugged_error_counts_as_unplugged() {
        assert!(is_unplugged(&unplugged()));
        assert!(!is_unplugged(&io::Error::other("device gone")));
        assert!(!is_unplugged(&crate::shutdown::shutdown_error()));
        assert!(!is_shutdown(&unplugged()));
    }
}
