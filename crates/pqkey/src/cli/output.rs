//! Standard output for the commands.  `println!` panics when standard
//! output fails; these return the error instead.

use std::{
    fmt,
    io::{self, Write},
};

/// Write `args` and a newline to standard output.
pub fn line(args: fmt::Arguments<'_>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{args}").and_then(|()| out.flush())
}

/// `println!` that returns an [`io::Error`] instead of panicking.
macro_rules! outln {
    () => {
        $crate::cli::output::line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::cli::output::line(format_args!($($arg)*))
    };
}
pub(crate) use outln;
