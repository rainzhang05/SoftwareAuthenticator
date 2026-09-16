//! Reading PINs for the `pin` subcommands.
//!
//! When stdin is a terminal the PIN is read with echo turned off, so it never
//! appears on screen or in scrollback, and a new PIN has to be typed twice.
//! Otherwise (a pipe or a file) each PIN is one line of stdin, read without a
//! prompt, so scripts can supply PINs without putting them on the command line.

use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    sync::atomic::{AtomicI32, Ordering},
};

use nix::{
    errno::Errno,
    libc,
    sys::{
        signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal},
        termios::{self, LocalFlags, SetArg, Termios},
    },
};
use zeroize::{Zeroize, Zeroizing};

use crate::service;

/// A PIN as read from the user; wiped from memory when dropped.
pub type Pin = Zeroizing<String>;

/// No valid PIN comes anywhere near this long; stop reading instead of
/// buffering arbitrary amounts of input.
const MAX_INPUT_BYTES: usize = 1024;

/// Reads PINs from stdin, interactively or not depending on what stdin is.
pub struct PinReader {
    interactive: bool,
}

impl PinReader {
    pub fn from_stdin() -> Self {
        Self {
            interactive: io::stdin().is_terminal(),
        }
    }

    pub fn current_pin(&self) -> io::Result<Pin> {
        self.read("Current PIN: ")
    }

    /// Read and validate a new PIN, asking for it twice on a terminal.
    pub fn new_pin(&self) -> io::Result<Pin> {
        read_new_pin(self.interactive, |prompt| self.read(prompt))
    }

    fn read(&self, prompt: &str) -> io::Result<Pin> {
        if self.interactive {
            read_hidden_line(io::stdin().as_fd(), &mut io::stderr(), prompt)
        } else {
            read_line(&mut io::stdin().lock())
        }
    }
}

fn read_new_pin(confirm: bool, mut read: impl FnMut(&str) -> io::Result<Pin>) -> io::Result<Pin> {
    let pin = read("New PIN: ")?;
    service::validate_pin(&pin)?;
    if confirm {
        let again = read("Confirm new PIN: ")?;
        if *again != *pin {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the two PINs do not match",
            ));
        }
    }
    Ok(pin)
}

/// Read one line, without its line ending, from non-terminal input.
fn read_line(input: &mut impl BufRead) -> io::Result<Pin> {
    let mut line = Zeroizing::new(Vec::with_capacity(128));
    input
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if line.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "expected a PIN on standard input",
        ));
    }
    finish_line(line)
}

/// Prompt on `prompt_output`, then read one line from the terminal `tty` with
/// echo turned off.
///
/// SIGINT, SIGTERM, SIGHUP and SIGQUIT are caught while echo is off. The
/// terminal settings are restored first and the signal is then raised again
/// with its previous disposition, so Ctrl-C still ends the program but never
/// leaves the terminal without echo.
fn read_hidden_line(
    tty: BorrowedFd<'_>,
    prompt_output: &mut impl Write,
    prompt: &str,
) -> io::Result<Pin> {
    prompt_output.write_all(prompt.as_bytes())?;
    prompt_output.flush()?;

    let catcher = SignalCatcher::install()?;
    let result = EchoDisabled::new(tty).and_then(|_echo_disabled| read_tty_line(tty));
    // `_echo_disabled` has been dropped, so the terminal is back to normal.
    if let Some(signal) = catcher.restore() {
        let _ = prompt_output.write_all(b"\n");
        let _ = prompt_output.flush();
        signal::raise(signal)?;
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "interrupted while reading the PIN",
        ));
    }
    result
}

fn read_tty_line(tty: BorrowedFd<'_>) -> io::Result<Pin> {
    let mut line = Zeroizing::new(Vec::with_capacity(128));
    let mut chunk = Zeroizing::new([0u8; 128]);
    loop {
        if SignalCatcher::caught().is_some() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        // The terminal is in canonical mode, so a read returns at most one
        // line and the kernel handles backspace and friends.
        match nix::unistd::read(tty.as_raw_fd(), &mut chunk[..]) {
            Ok(0) if line.is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no PIN was entered",
                ))
            }
            Ok(0) => break,
            Ok(read) => {
                line.extend_from_slice(&chunk[..read]);
                if line.ends_with(b"\n") || line.len() > MAX_INPUT_BYTES {
                    break;
                }
            }
            Err(Errno::EINTR) => continue,
            Err(err) => return Err(err.into()),
        }
    }
    finish_line(line)
}

/// Strip the line ending and check the result is a plausible PIN string.
fn finish_line(mut line: Zeroizing<Vec<u8>>) -> io::Result<Pin> {
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    if line.len() > MAX_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PIN input is too long",
        ));
    }
    match String::from_utf8(std::mem::take(&mut *line)) {
        Ok(pin) => Ok(Zeroizing::new(pin)),
        Err(err) => {
            err.into_bytes().zeroize();
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PIN is not valid UTF-8",
            ))
        }
    }
}

/// Turns terminal echo off, and back on when dropped.
struct EchoDisabled<'fd> {
    tty: BorrowedFd<'fd>,
    saved: Termios,
}

impl<'fd> EchoDisabled<'fd> {
    fn new(tty: BorrowedFd<'fd>) -> io::Result<Self> {
        let saved = termios::tcgetattr(tty)?;
        let mut quiet = saved.clone();
        quiet.local_flags.remove(LocalFlags::ECHO);
        // Still echo the newline, so output continues on the next line.
        quiet.local_flags.insert(LocalFlags::ECHONL);
        // TCSAFLUSH discards anything typed ahead while echo was still on.
        termios::tcsetattr(tty, SetArg::TCSAFLUSH, &quiet)?;
        Ok(Self { tty, saved })
    }
}

impl Drop for EchoDisabled<'_> {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(self.tty, SetArg::TCSAFLUSH, &self.saved);
    }
}

/// Signals whose default action would end the process while echo is off.
const CAUGHT_SIGNALS: [Signal; 4] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
];

static CAUGHT_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(signal: libc::c_int) {
    CAUGHT_SIGNAL.store(signal, Ordering::SeqCst);
}

/// Records [`CAUGHT_SIGNALS`] instead of acting on them, until restored.
struct SignalCatcher {
    previous: Vec<(Signal, SigAction)>,
}

impl SignalCatcher {
    fn install() -> io::Result<Self> {
        CAUGHT_SIGNAL.store(0, Ordering::SeqCst);
        // No SA_RESTART: a read blocked on the terminal must return EINTR.
        let action = SigAction::new(
            SigHandler::Handler(record_signal),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let mut catcher = Self {
            previous: Vec::with_capacity(CAUGHT_SIGNALS.len()),
        };
        for signal in CAUGHT_SIGNALS {
            // SAFETY: the handler only stores into an atomic, which is
            // async-signal-safe.
            let previous = unsafe { signal::sigaction(signal, &action) }?;
            catcher.previous.push((signal, previous));
        }
        Ok(catcher)
    }

    fn caught() -> Option<Signal> {
        Signal::try_from(CAUGHT_SIGNAL.load(Ordering::SeqCst)).ok()
    }

    /// Reinstate the previous handlers and return the signal caught, if any.
    fn restore(mut self) -> Option<Signal> {
        self.reinstate();
        Signal::try_from(CAUGHT_SIGNAL.swap(0, Ordering::SeqCst)).ok()
    }

    fn reinstate(&mut self) {
        for (signal, previous) in self.previous.drain(..) {
            // SAFETY: puts back exactly the action that was installed before.
            let _ = unsafe { signal::sigaction(signal, &previous) };
        }
    }
}

impl Drop for SignalCatcher {
    fn drop(&mut self) {
        self.reinstate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        fs::File,
        io::Cursor,
        thread,
        time::{Duration, Instant},
    };

    fn pin(value: &str) -> Pin {
        Zeroizing::new(value.to_owned())
    }

    #[test]
    fn piped_input_yields_one_pin_per_line() {
        let mut input = Cursor::new(b"1234\n5678\r\nlast".to_vec());
        assert_eq!(*read_line(&mut input).unwrap(), "1234");
        assert_eq!(*read_line(&mut input).unwrap(), "5678");
        assert_eq!(*read_line(&mut input).unwrap(), "last");
        let err = read_line(&mut input).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn piped_input_keeps_the_pin_exactly() {
        let mut input = Cursor::new(" 12 \t34 \n".as_bytes().to_vec());
        assert_eq!(*read_line(&mut input).unwrap(), " 12 \t34 ");
        let mut input = Cursor::new("\u{e9}t\u{e9}!\n".as_bytes().to_vec());
        assert_eq!(*read_line(&mut input).unwrap(), "\u{e9}t\u{e9}!");
    }

    #[test]
    fn piped_input_rejects_bad_lines() {
        let mut input = Cursor::new(vec![0xff, 0xfe, b'\n']);
        assert_eq!(
            read_line(&mut input).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut input = Cursor::new(vec![b'1'; MAX_INPUT_BYTES + 10]);
        assert_eq!(
            read_line(&mut input).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    fn scripted(lines: &[&str]) -> (VecDeque<Pin>, Vec<String>) {
        (lines.iter().map(|line| pin(line)).collect(), Vec::new())
    }

    #[test]
    fn new_pin_is_confirmed_when_interactive() {
        let (mut lines, mut prompts) = scripted(&["1234", "1234"]);
        let result = read_new_pin(true, |prompt| {
            prompts.push(prompt.to_owned());
            Ok(lines.pop_front().unwrap())
        });
        assert_eq!(*result.unwrap(), "1234");
        assert_eq!(prompts, ["New PIN: ", "Confirm new PIN: "]);
    }

    #[test]
    fn mismatched_confirmation_is_rejected() {
        let (mut lines, _) = scripted(&["1234", "1243"]);
        let err = read_new_pin(true, |_| Ok(lines.pop_front().unwrap())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn new_pin_is_read_once_when_not_interactive() {
        let (mut lines, _) = scripted(&["1234"]);
        let result = read_new_pin(false, |_| Ok(lines.pop_front().unwrap()));
        assert_eq!(*result.unwrap(), "1234");
    }

    #[test]
    fn invalid_new_pin_is_rejected_before_confirmation() {
        let mut reads = 0;
        let err = read_new_pin(true, |_| {
            reads += 1;
            Ok(pin("12"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(reads, 1);
    }

    fn echo_enabled(tty: &File) -> bool {
        termios::tcgetattr(tty)
            .unwrap()
            .local_flags
            .contains(LocalFlags::ECHO)
    }

    #[test]
    fn terminal_input_is_not_echoed_and_echo_is_restored() {
        let pty = nix::pty::openpty(None, None).expect("openpty");
        let mut terminal = File::from(pty.master);
        let tty = File::from(pty.slave);
        assert!(echo_enabled(&tty));

        let reader_tty = tty.try_clone().unwrap();
        let reader = thread::spawn(move || {
            let mut prompt = Vec::new();
            let pin = read_hidden_line(reader_tty.as_fd(), &mut prompt, "PIN: ");
            (pin, prompt)
        });

        // Type only once echo is off: turning it off flushes typed-ahead input.
        let deadline = Instant::now() + Duration::from_secs(10);
        while echo_enabled(&tty) {
            assert!(Instant::now() < deadline, "echo was never turned off");
            thread::sleep(Duration::from_millis(5));
        }
        terminal.write_all(b"s3cret-PIN\n").unwrap();

        // Collect what the terminal displays while the reader finishes, like a
        // terminal emulator would: restoring the settings waits for the output
        // queue to drain.
        nix::fcntl::fcntl(
            terminal.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .unwrap();
        let mut displayed = Vec::new();
        let mut buf = [0u8; 256];
        let mut drain = |displayed: &mut Vec<u8>| loop {
            match terminal.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => displayed.extend_from_slice(&buf[..read]),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("reading the terminal output failed: {err}"),
            }
        };
        while !reader.is_finished() {
            assert!(Instant::now() < deadline, "the PIN was never read");
            drain(&mut displayed);
            thread::sleep(Duration::from_millis(5));
        }
        drain(&mut displayed);

        let (pin, prompt) = reader.join().unwrap();
        assert_eq!(*pin.unwrap(), "s3cret-PIN");
        assert_eq!(prompt, b"PIN: ");
        assert!(echo_enabled(&tty), "echo was not restored");
        let displayed = String::from_utf8_lossy(&displayed);
        assert!(
            !displayed.contains("s3cret"),
            "PIN was echoed: {displayed:?}"
        );
        assert!(
            displayed.contains('\n'),
            "newline was not echoed: {displayed:?}"
        );
    }
}
