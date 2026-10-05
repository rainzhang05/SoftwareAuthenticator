//! The running key's hidraw node: finding it, and exchanging reports with it.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsFd,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};

use crate::client::ctaphid::{Report, ReportLink};
use crate::transport::CTAPHID_FRAME_LEN;

/// The hidraw node of the HID device whose unique identifier is `uniq`
/// (`HID_UNIQ` in its uevent), with sysfs's `class/hidraw` at `sys_hidraw`
/// and the nodes in `dev`.
pub fn find_node(sys_hidraw: &Path, dev: &Path, uniq: &str) -> io::Result<Option<PathBuf>> {
    let entries = match fs::read_dir(sys_hidraw) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    for entry in entries.flatten() {
        let Ok(uevent) = fs::read_to_string(entry.path().join("device").join("uevent")) else {
            continue;
        };
        if uevent
            .lines()
            .any(|line| line.strip_prefix("HID_UNIQ=") == Some(uniq))
        {
            return Ok(Some(dev.join(entry.file_name())));
        }
    }
    Ok(None)
}

/// [`find_node`] in the system's sysfs and `/dev`.
pub fn find_system_node(uniq: &str) -> io::Result<Option<PathBuf>> {
    find_node(Path::new("/sys/class/hidraw"), Path::new("/dev"), uniq)
}

/// Reports through a hidraw node.
pub struct Hidraw {
    file: File,
}

impl Hidraw {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: OpenOptions::new().read(true).write(true).open(path)?,
        })
    }
}

impl ReportLink for Hidraw {
    fn send(&mut self, report: &Report) -> io::Result<()> {
        // The report descriptor has no report IDs, so hidraw takes a zero
        // first byte in front of the report.
        let mut buffer = [0u8; CTAPHID_FRAME_LEN + 1];
        buffer[1..].copy_from_slice(report);
        self.file.write_all(&buffer)
    }

    fn receive(&mut self, timeout: Duration) -> io::Result<Option<Report>> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let mut fds = [PollFd::new(self.file.as_fd(), PollFlags::POLLIN)];
            match poll(
                &mut fds,
                PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX),
            ) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                // A signal, such as the Ctrl-C that cancels a request, ends
                // the wait early; it goes on for the time left.
                Err(Errno::EINTR) => {}
                Err(err) => return Err(err.into()),
            }
        }
        let mut report = [0u8; CTAPHID_FRAME_LEN];
        let read = loop {
            match self.file.read(&mut report) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                other => break other?,
            }
        };
        if read != CTAPHID_FRAME_LEN {
            return Err(io::Error::other(format!("a {read}-byte report")));
        }
        Ok(Some(report))
    }
}

fn open_node(uniq: &str, wait: Duration) -> io::Result<(PathBuf, Hidraw)> {
    let pid = uniq.strip_prefix("pqkey-").unwrap_or(uniq);
    let deadline = Instant::now() + wait;
    loop {
        let waited = Instant::now() >= deadline;
        match find_system_node(uniq)? {
            Some(path) => match Hidraw::open(&path) {
                Ok(link) => return Ok((path, link)),
                // udev has not granted access yet.
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied && !waited => {}
                Err(err) => {
                    return Err(io::Error::new(
                        err.kind(),
                        format!(
                            "cannot open the key's device {}: {err}; `pqkey status` shows why",
                            path.display()
                        ),
                    ));
                }
            },
            None if waited => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("the key runs (pid {pid}), but its device is missing"),
                ));
            }
            None => {}
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Open the daemon's client device, returning its display label and reports.
pub fn open_client(uniq: &str, wait: Duration) -> io::Result<(String, Hidraw)> {
    open_node(uniq, wait).map(|(path, link)| (path.display().to_string(), link))
}

pub(crate) fn device_problems(
    system: &super::checks::System,
    pid: nix::unistd::Pid,
    wait: Duration,
) -> Vec<super::checks::Problem> {
    use super::checks::Problem;
    let uniq = crate::service::device_uniq(pid.as_raw().unsigned_abs());
    let mut problems = Vec::new();
    match open_node(&uniq, wait) {
        Ok((node, _)) => problems.extend(super::checks::browser_problems(system, &node, &Ok(()))),
        Err(err) => match find_system_node(&uniq) {
            Ok(Some(node)) => {
                problems.extend(super::checks::browser_problems(system, &node, &Err(err)));
            }
            _ => problems.push(Problem {
                what: format!("the key runs (pid {}), but its device is missing", pid),
                fix: "run `pqkey stop && pqkey start`".into(),
            }),
        },
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::{
        sync::{Arc, atomic::AtomicBool},
        thread,
    };

    /// A signal while the client waits for the key, such as the Ctrl-C that
    /// cancels a request, does not end the wait: the cancellation still has
    /// to reach the key, and its answer to come back.
    #[test]
    fn a_signal_does_not_end_the_wait_for_a_report() {
        use nix::sys::{pthread, signal::Signal, stat::Mode};
        let _serialized = crate::test_support::lock_signal_handlers();
        let dir = TempDir::new("hidraw-eintr");
        // A FIFO stands in for the node: opened for reading and writing, it
        // blocks reads until a report is written.
        let node = dir.path().join("hidraw0");
        nix::unistd::mkfifo(&node, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        let mut link = Hidraw::open(&node).unwrap();
        let handler =
            signal_hook::flag::register(Signal::SIGUSR2 as i32, Arc::new(AtomicBool::new(false)))
                .unwrap();
        let waiting = pthread::pthread_self();
        let key = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            pthread::pthread_kill(waiting, Signal::SIGUSR2).unwrap();
            thread::sleep(Duration::from_millis(100));
            OpenOptions::new()
                .write(true)
                .open(&node)
                .unwrap()
                .write_all(&[0x42; CTAPHID_FRAME_LEN])
                .unwrap();
        });
        let report = link.receive(Duration::from_secs(10));
        key.join().unwrap();
        signal_hook::low_level::unregister(handler);
        assert_eq!(report.unwrap(), Some([0x42; CTAPHID_FRAME_LEN]));
    }

    #[test]
    fn the_node_is_found_by_its_unique_identifier() {
        let dir = TempDir::new("hidraw-uniq");
        let sys = dir.path().join("sys");
        for (name, uniq) in [
            ("hidraw1", "pqkey-41"),
            ("hidraw2", "pqkey-42"),
            ("hidraw3", ""),
        ] {
            let device = sys.join(name).join("device");
            fs::create_dir_all(&device).unwrap();
            fs::write(
                device.join("uevent"),
                format!("HID_ID=0003:00001209:00000001\nHID_UNIQ={uniq}\n"),
            )
            .unwrap();
        }
        let dev = dir.path().join("dev");
        assert_eq!(
            find_node(&sys, &dev, "pqkey-42").unwrap(),
            Some(dev.join("hidraw2"))
        );
        assert_eq!(find_node(&sys, &dev, "pqkey-4").unwrap(), None);
        assert_eq!(
            find_node(&dir.path().join("absent"), &dev, "pqkey-42").unwrap(),
            None
        );
    }
}
