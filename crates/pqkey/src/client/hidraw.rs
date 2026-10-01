//! The running key's hidraw node: finding it, and exchanging reports with it.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsFd,
    path::{Path, PathBuf},
    time::Duration,
};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use super::ctaphid::{Report, ReportLink};
use crate::uhid::CTAPHID_FRAME_LEN;

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
        let mut fds = [PollFd::new(self.file.as_fd(), PollFlags::POLLIN)];
        let timeout = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX);
        if poll(&mut fds, timeout).map_err(io::Error::from)? == 0 {
            return Ok(None);
        }
        let mut report = [0u8; CTAPHID_FRAME_LEN];
        let read = self.file.read(&mut report)?;
        if read != CTAPHID_FRAME_LEN {
            return Err(io::Error::other(format!("a {read}-byte report")));
        }
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

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
