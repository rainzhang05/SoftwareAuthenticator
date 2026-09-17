//! Exclusive use of a state directory, and the pid file that goes with it.
//!
//! The daemon, and every command that opens the stored state (`pin`,
//! `reset`), hold an exclusive `flock` on `authenticator.lock` for as long as
//! they use the directory. So two daemons never run on the same state, the
//! CLI never changes a PIN underneath a running daemon, and two CLI commands
//! cannot interleave their reads and writes of the retry counter. The kernel
//! releases the lock when the holder exits, however it exits.
//!
//! The lock is also what makes the pid file trustworthy: `status` and
//! `detach` only use the pid while the lock is held, so a pid file left
//! behind by a killed daemon never gets an unrelated process signalled after
//! its pid has been reused.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process, thread,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
    unistd::Pid,
};

pub const LOCK_FILE: &str = "authenticator.lock";
pub const PID_FILE: &str = "authenticator.pid";

/// How long [`StateLock::try_acquire`] keeps trying. [`is_locked`] takes a
/// shared lock for an instant, and must not make a starting daemon give up.
const ACQUIRE_PATIENCE: Duration = Duration::from_millis(250);

/// Exclusive hold on a state directory, released when dropped.
#[derive(Debug)]
pub struct StateLock {
    /// Holds the lock; dropping it unlocks and closes the file.
    _flock: Flock<File>,
}

impl StateLock {
    /// Take the lock, or return `None` if another process holds it.
    pub fn try_acquire(state_dir: &Path) -> io::Result<Option<Self>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(state_dir.join(LOCK_FILE))?;
        let deadline = Instant::now() + ACQUIRE_PATIENCE;
        // `Flock::lock` takes the file by value and hands it back with the
        // error, so each retry locks the file it just got back.
        let mut file = file;
        loop {
            match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
                Ok(flock) => return Ok(Some(Self { _flock: flock })),
                Err((returned, Errno::EWOULDBLOCK)) if Instant::now() < deadline => {
                    file = returned;
                    thread::sleep(Duration::from_millis(10));
                }
                Err((_, Errno::EWOULDBLOCK)) => return Ok(None),
                Err((returned, Errno::EINTR)) => file = returned,
                Err((_, err)) => return Err(err.into()),
            }
        }
    }
}

/// Whether another process holds the lock on `state_dir`.
pub fn is_locked(state_dir: &Path) -> io::Result<bool> {
    let file = match File::open(state_dir.join(LOCK_FILE)) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let mut file = file;
    loop {
        // A shared lock conflicts only with an exclusive holder. It is
        // released again when the `Flock` is dropped on return.
        match Flock::lock(file, FlockArg::LockSharedNonblock) {
            Ok(_flock) => return Ok(false),
            Err((_, Errno::EWOULDBLOCK)) => return Ok(true),
            Err((returned, Errno::EINTR)) => file = returned,
            Err((_, err)) => return Err(err.into()),
        }
    }
}

/// What `status` and `detach` can tell about a state directory.
#[derive(Debug, PartialEq, Eq)]
pub enum DaemonState {
    /// Nothing holds the lock; any pid file is stale.
    Stopped,
    /// The lock is held and the daemon has published its pid.
    Running(Pid),
    /// The lock is held but there is no pid: a daemon that has not finished
    /// starting, or a `pin` or `reset` command.
    Busy,
}

pub fn daemon_state(state_dir: &Path) -> io::Result<DaemonState> {
    if !is_locked(state_dir)? {
        return Ok(DaemonState::Stopped);
    }
    Ok(match read_pid(state_dir)? {
        Some(pid) => DaemonState::Running(pid),
        None => DaemonState::Busy,
    })
}

/// Read the pid file. Content that does not parse counts as no pid.
pub fn read_pid(state_dir: &Path) -> io::Result<Option<Pid>> {
    match fs::read_to_string(state_dir.join(PID_FILE)) {
        Ok(contents) => Ok(contents.trim().parse::<i32>().ok().map(Pid::from_raw)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Publish this process's pid. Only the holder of the lock may do this. The
/// file is replaced atomically, so readers never see a partial pid.
pub fn write_pid_file(state_dir: &Path, _lock: &StateLock) -> io::Result<()> {
    let pid = process::id();
    let path = state_dir.join(PID_FILE);
    let temporary = state_dir.join(format!("{PID_FILE}.{pid}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    writeln!(file, "{pid}")?;
    fs::rename(&temporary, path)
}

/// Remove the pid file. Only the holder of the lock may do this.
pub fn remove_pid_file(state_dir: &Path, _lock: &StateLock) -> io::Result<()> {
    match fs::remove_file(state_dir.join(PID_FILE)) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn lock_is_exclusive_until_dropped() {
        let dir = TempDir::new("lock-exclusive");
        let first = StateLock::try_acquire(dir.path()).unwrap();
        assert!(first.is_some());
        assert!(StateLock::try_acquire(dir.path()).unwrap().is_none());
        drop(first);
        assert!(StateLock::try_acquire(dir.path()).unwrap().is_some());
    }

    #[test]
    fn is_locked_reports_the_holder_without_taking_the_lock_away() {
        let dir = TempDir::new("lock-probe");
        assert!(!is_locked(dir.path()).unwrap(), "no lock file yet");
        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        assert!(is_locked(dir.path()).unwrap());
        assert!(is_locked(dir.path()).unwrap());
        drop(lock);
        assert!(!is_locked(dir.path()).unwrap());
        // Probing left nothing behind that would stop the next holder.
        assert!(StateLock::try_acquire(dir.path()).unwrap().is_some());
    }

    #[test]
    fn a_probe_in_progress_does_not_make_acquiring_fail() {
        let dir = TempDir::new("lock-probe-race");
        File::create(dir.path().join(LOCK_FILE)).unwrap();
        let probe = File::open(dir.path().join(LOCK_FILE)).unwrap();
        let probe = Flock::lock(probe, FlockArg::LockSharedNonblock).unwrap();
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(probe);
        });
        assert!(StateLock::try_acquire(dir.path()).unwrap().is_some());
        release.join().unwrap();
    }

    #[test]
    fn pid_file_is_only_trusted_while_the_lock_is_held() {
        let dir = TempDir::new("lock-pid");
        assert_eq!(daemon_state(dir.path()).unwrap(), DaemonState::Stopped);

        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        assert_eq!(daemon_state(dir.path()).unwrap(), DaemonState::Busy);
        write_pid_file(dir.path(), &lock).unwrap();
        let own_pid = Pid::from_raw(process::id() as i32);
        assert_eq!(read_pid(dir.path()).unwrap(), Some(own_pid));
        assert_eq!(
            daemon_state(dir.path()).unwrap(),
            DaemonState::Running(own_pid)
        );

        // A holder that dies without cleaning up leaves a stale pid file,
        // which must not be reported as a running daemon.
        drop(lock);
        assert_eq!(daemon_state(dir.path()).unwrap(), DaemonState::Stopped);

        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        remove_pid_file(dir.path(), &lock).unwrap();
        remove_pid_file(dir.path(), &lock).unwrap();
        assert_eq!(read_pid(dir.path()).unwrap(), None);
    }

    #[test]
    fn unparsable_pid_file_counts_as_no_pid() {
        let dir = TempDir::new("lock-bad-pid");
        fs::write(dir.path().join(PID_FILE), "not a pid\n").unwrap();
        assert_eq!(read_pid(dir.path()).unwrap(), None);
        assert!(dir.path().join(PID_FILE).exists());
    }
}
