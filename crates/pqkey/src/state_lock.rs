//! Exclusive use of a state directory, and the pid file that goes with it.
//!
//! The daemon holds an exclusive `flock` on `authenticator.lock` for as long
//! as it uses the directory, so two daemons never run on the same state. The
//! kernel releases the lock when the holder exits, however it exits.
//!
//! The lock is also what makes the pid file trustworthy: `status` and `stop`
//! only use the pid while the lock is held, and whoever takes the lock first
//! removes a pid file left behind by a killed daemon. So such a pid is not
//! signalled after it has been reused by an unrelated process, unless a
//! `stop` reads it in the moment between the two.

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

use crate::state::path_error;

pub const LOCK_FILE: &str = "authenticator.lock";
pub const PID_FILE: &str = "authenticator.pid";
pub const INFO_FILE: &str = "authenticator.info";

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
    /// Take the lock, or return `None` if another process holds it. An error
    /// names the lock file.
    pub fn try_acquire(state_dir: &Path) -> io::Result<Option<Self>> {
        let path = state_dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|err| path_error(err, "open", &path))?;
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
                Err((_, err)) => return Err(path_error(err.into(), "lock", &path)),
            }
        }
    }
}

/// Whether another process holds the lock on `state_dir`. An error names the
/// lock file.
pub fn is_locked(state_dir: &Path) -> io::Result<bool> {
    let path = state_dir.join(LOCK_FILE);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(path_error(err, "open", &path)),
    };
    let mut file = file;
    loop {
        // A shared lock conflicts only with an exclusive holder. It is
        // released again when the `Flock` is dropped on return.
        match Flock::lock(file, FlockArg::LockSharedNonblock) {
            Ok(_flock) => return Ok(false),
            Err((_, Errno::EWOULDBLOCK)) => return Ok(true),
            Err((returned, Errno::EINTR)) => file = returned,
            Err((_, err)) => return Err(path_error(err.into(), "lock", &path)),
        }
    }
}

/// What `status` and `stop` can tell about a state directory.
#[derive(Debug, PartialEq, Eq)]
pub enum DaemonState {
    /// Nothing holds the lock; any pid file is stale.
    Stopped,
    /// The lock is held and the daemon has published its pid.
    Running(Pid),
    /// The lock is held but there is no pid: a daemon that is starting or
    /// stopping.
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

/// Read the pid file. Content that does not parse counts as no pid, and so
/// does a pid that no daemon can have: 0, 1 (init), or a negative number,
/// which kill(2) would take for a process group or for every process. An
/// error names the pid file.
pub fn read_pid(state_dir: &Path) -> io::Result<Option<Pid>> {
    let path = state_dir.join(PID_FILE);
    match fs::read_to_string(&path) {
        Ok(contents) => Ok(contents
            .trim()
            .parse::<i32>()
            .ok()
            .filter(|&pid| pid > 1)
            .map(Pid::from_raw)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(path_error(err, "read", &path)),
    }
}

/// Publish this process's pid. Only the holder of the lock may do this. The
/// file is replaced atomically, so readers never see a partial pid.
pub fn write_pid_file(state_dir: &Path, _lock: &StateLock) -> io::Result<()> {
    write_file(
        state_dir,
        PID_FILE,
        format!("{}\n", process::id()).as_bytes(),
    )
}

/// Publish non-secret daemon information atomically, before its ready pid.
pub fn write_info_file(state_dir: &Path, _lock: &StateLock, bytes: &[u8]) -> io::Result<()> {
    write_file(state_dir, INFO_FILE, bytes)
}

/// Replace `state_dir/name` with `bytes`. An error names that file.
fn write_file(state_dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let path = state_dir.join(name);
    let failed = |err| path_error(err, "write", &path);
    let temporary = state_dir.join(format!("{name}.{}.tmp", process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(failed)?;
    file.write_all(bytes).map_err(failed)?;
    fs::rename(&temporary, &path).map_err(failed)
}

/// Remove the pid file. Only the holder of the lock may do this.
pub fn remove_pid_file(state_dir: &Path, _lock: &StateLock) -> io::Result<()> {
    remove_file(state_dir, PID_FILE)
}

/// Remove daemon information while its state directory is exclusively held.
pub fn remove_info_file(state_dir: &Path, _lock: &StateLock) -> io::Result<()> {
    remove_file(state_dir, INFO_FILE)
}

/// Remove `state_dir/name`, if it exists. An error names that file.
fn remove_file(state_dir: &Path, name: &str) -> io::Result<()> {
    let path = state_dir.join(name);
    match fs::remove_file(&path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(path_error(err, "remove", &path)),
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

    /// A failed write of the pid file or of the daemon's information names
    /// the file, here on a full disk as /dev/full plays one: the temporary
    /// file each is written to first is a link to it. So does a lock file
    /// that cannot be opened, to take the lock or to look at it, a pid file
    /// that cannot be read, and a file that cannot be removed.
    #[test]
    fn a_state_file_that_fails_is_named() {
        let dir = TempDir::new("lock-dev-full");
        let lock = StateLock::try_acquire(dir.path()).unwrap().unwrap();
        for name in [PID_FILE, INFO_FILE] {
            let temporary = dir.path().join(format!("{name}.{}.tmp", process::id()));
            std::os::unix::fs::symlink("/dev/full", temporary).unwrap();
        }
        for (result, name) in [
            (write_pid_file(dir.path(), &lock), PID_FILE),
            (write_info_file(dir.path(), &lock, b"info"), INFO_FILE),
        ] {
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::StorageFull);
            assert_eq!(
                err.to_string(),
                format!(
                    "cannot write {}: No space left on device (os error 28)",
                    dir.path().join(name).display()
                )
            );
        }
        let missing = dir.path().join("missing");
        assert_eq!(
            StateLock::try_acquire(&missing).unwrap_err().to_string(),
            format!(
                "cannot open {}: No such file or directory (os error 2)",
                missing.join(LOCK_FILE).display()
            )
        );
        let file = dir.path().join("file");
        fs::write(&file, b"").unwrap();
        assert_eq!(
            is_locked(&file).unwrap_err().to_string(),
            format!(
                "cannot open {}: Not a directory (os error 20)",
                file.join(LOCK_FILE).display()
            )
        );
        fs::create_dir(dir.path().join(PID_FILE)).unwrap();
        assert_eq!(
            read_pid(dir.path()).unwrap_err().to_string(),
            format!(
                "cannot read {}: Is a directory (os error 21)",
                dir.path().join(PID_FILE).display()
            )
        );
        assert_eq!(
            remove_pid_file(dir.path(), &lock).unwrap_err().to_string(),
            format!(
                "cannot remove {}: Is a directory (os error 21)",
                dir.path().join(PID_FILE).display()
            )
        );
    }

    #[test]
    fn unparsable_pid_file_counts_as_no_pid() {
        let dir = TempDir::new("lock-bad-pid");
        fs::write(dir.path().join(PID_FILE), "not a pid\n").unwrap();
        assert_eq!(read_pid(dir.path()).unwrap(), None);
        assert!(dir.path().join(PID_FILE).exists());
    }

    #[test]
    fn a_pid_no_daemon_can_have_counts_as_no_pid() {
        let dir = TempDir::new("lock-no-daemon-pid");
        // kill(2) takes 0 for its caller's process group, -1 for every process
        // it may signal and other negative pids for process groups; 1 is init.
        for pid in ["0", "1", "-1", "-4242"] {
            fs::write(dir.path().join(PID_FILE), format!("{pid}\n")).unwrap();
            assert_eq!(read_pid(dir.path()).unwrap(), None, "pid file {pid}");
        }
        fs::write(dir.path().join(PID_FILE), "4242\n").unwrap();
        assert_eq!(read_pid(dir.path()).unwrap(), Some(Pid::from_raw(4242)));
    }
}
