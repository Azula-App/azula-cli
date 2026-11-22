//! EPIPE-safe stdout for the client verbs.
//!
//! `println!` panics when stdout is a closed pipe (`azula compute jobs | head`),
//! and resetting SIGPIPE to its default globally would make the process die on
//! a broken *relay* socket instead of reconnecting. So writes to stdout go
//! through these helpers: a `BrokenPipe` ends the process quietly with 141
//! (128 + SIGPIPE, what a shell reports), anything else is ignored like
//! stderr. Jobs outlive the connection, so exiting while streaming output
//! leaves the job running, exactly like a detach.

use std::fmt;
use std::io::{self, Write};

/// Exit status after the reader of our stdout went away.
pub const EXIT_SIGPIPE: i32 = 141;

/// Is `e` the reader having closed the pipe?
pub fn is_broken_pipe(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::BrokenPipe
}

/// Exit quietly with 141 if `e` is a broken pipe; otherwise do nothing.
pub fn exit_on_broken_pipe(e: &io::Error) {
    if is_broken_pipe(e) {
        std::process::exit(EXIT_SIGPIPE);
    }
}

/// Write formatted text (and a newline when `newline`) to stdout, EPIPE-safe.
pub fn print_args(args: fmt::Arguments<'_>, newline: bool) {
    let mut o = io::stdout().lock();
    let r = o.write_fmt(args).and_then(|()| if newline { o.write_all(b"\n") } else { Ok(()) });
    if let Err(e) = r {
        exit_on_broken_pipe(&e);
    }
}

/// Write raw bytes to stdout and flush, EPIPE-safe.
pub fn write_bytes(data: &[u8]) {
    let mut o = io::stdout().lock();
    if let Err(e) = o.write_all(data).and_then(|()| o.flush()) {
        exit_on_broken_pipe(&e);
    }
}

/// `println!` that exits 141 quietly on a closed pipe instead of panicking.
#[macro_export]
macro_rules! outln {
    () => { $crate::compute::out::print_args(format_args!(""), true) };
    ($($arg:tt)*) => { $crate::compute::out::print_args(format_args!($($arg)*), true) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_broken_pipe_is_special() {
        assert!(is_broken_pipe(&io::Error::from(io::ErrorKind::BrokenPipe)));
        assert!(!is_broken_pipe(&io::Error::from(io::ErrorKind::PermissionDenied)));
        // Non-EPIPE errors must not exit the test process.
        exit_on_broken_pipe(&io::Error::from(io::ErrorKind::Other));
        assert_eq!(EXIT_SIGPIPE, 128 + 13);
    }
}
