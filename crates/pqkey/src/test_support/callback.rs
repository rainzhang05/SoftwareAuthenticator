//! A callback device: reports are queued separately from its readiness socket.

use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::net::UnixStream,
    },
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use crate::transport::{CtapHidFrame, HidDevice};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

#[derive(Debug)]
pub(crate) enum Event {
    Report(CtapHidFrame),
    Destroyed,
}

pub(crate) struct Device {
    queue: Arc<Mutex<VecDeque<CtapHidFrame>>>,
    ready: UnixStream,
    reports: mpsc::Sender<Event>,
}

#[derive(Clone)]
pub(crate) struct Peer {
    queue: Arc<Mutex<VecDeque<CtapHidFrame>>>,
    ready: Arc<UnixStream>,
    reports: Arc<Mutex<mpsc::Receiver<Event>>>,
}

pub(crate) fn pair() -> (Device, Peer) {
    let (reader, writer) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    writer.set_nonblocking(true).unwrap();
    let queue = Arc::new(Mutex::new(VecDeque::new()));
    let (sender, receiver) = mpsc::channel();
    (
        Device {
            queue: Arc::clone(&queue),
            ready: reader,
            reports: sender,
        },
        Peer {
            queue,
            ready: Arc::new(writer),
            reports: Arc::new(Mutex::new(receiver)),
        },
    )
}

impl HidDevice for Device {
    fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>> {
        let mut bytes = [0; 64];
        loop {
            match (&self.ready).read(&mut bytes) {
                Ok(0) => break,
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        Ok(self.queue.lock().unwrap().pop_front())
    }

    fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()> {
        self.reports
            .send(Event::Report(*frame))
            .map_err(io::Error::other)
    }

    fn wait_with(&self, other: BorrowedFd<'_>, timeout: Option<Duration>) -> io::Result<bool> {
        if !self.queue.lock().unwrap().is_empty() {
            return Ok(true);
        }
        let mut fds = [
            PollFd::new(self.ready.as_fd(), PollFlags::POLLIN),
            PollFd::new(other, PollFlags::POLLIN),
        ];
        let timeout = timeout.map_or(PollTimeout::NONE, |duration| {
            PollTimeout::try_from(duration).unwrap_or(PollTimeout::MAX)
        });
        match poll(&mut fds, timeout) {
            Ok(ready) => Ok(ready > 0),
            Err(nix::errno::Errno::EINTR) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.reports.send(Event::Destroyed);
    }
}

impl Peer {
    pub(crate) fn send(&self, frame: &[u8; 64]) -> io::Result<()> {
        self.queue
            .lock()
            .unwrap()
            .push_back(CtapHidFrame::new(*frame));
        match (&*self.ready).write(&[0]) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    pub(crate) fn read_event(&mut self) -> io::Result<Event> {
        self.reports
            .lock()
            .unwrap()
            .recv()
            .map_err(io::Error::other)
    }

    pub(crate) fn receive(&self, timeout: Duration) -> io::Result<Option<[u8; 64]>> {
        match self.reports.lock().unwrap().recv_timeout(timeout) {
            Ok(Event::Report(frame)) => Ok(Some(frame.0)),
            Ok(Event::Destroyed) => Err(io::ErrorKind::UnexpectedEof.into()),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(err) => Err(io::Error::other(err)),
        }
    }
}
