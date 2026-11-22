//! systemd socket activation (`--systemd-socket`): adopt the listening Unix
//! socket systemd passes as fd 3 (`LISTEN_PID`, `LISTEN_FDS`; sd_listen_fds(3)).

use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixListener;

/// First passed descriptor (`SD_LISTEN_FDS_START`).
pub const LISTEN_FDS_START: RawFd = 3;

/// Check the activation variables against our pid; returns how many
/// descriptors were passed. Pure, so it is unit-tested.
pub fn parse_listen_env(pid: u32, listen_pid: Option<&str>, listen_fds: Option<&str>) -> Result<u32, String> {
    let (Some(lp), Some(lf)) = (listen_pid, listen_fds) else {
        return Err("LISTEN_PID/LISTEN_FDS are not set: --systemd-socket needs a socket from systemd \
                    (run the worker from an azula-guest.socket unit)"
            .into());
    };
    let lp: u32 = lp.trim().parse().map_err(|_| format!("LISTEN_PID={lp:?} is not a pid"))?;
    if lp != pid {
        return Err(format!("LISTEN_PID={lp} is not this process ({pid}): the socket was meant for another process"));
    }
    let n: u32 = lf.trim().parse().map_err(|_| format!("LISTEN_FDS={lf:?} is not a number"))?;
    if n < 1 {
        return Err("LISTEN_FDS is 0: systemd passed no socket".into());
    }
    Ok(n)
}

/// Take the activated listener from fd 3 and unset the activation variables
/// so they are not inherited by jobs.
pub fn systemd_listener() -> Result<UnixListener, String> {
    let r = parse_listen_env(std::process::id(), std::env::var("LISTEN_PID").ok().as_deref(), std::env::var("LISTEN_FDS").ok().as_deref());
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    r?;
    let fd = LISTEN_FDS_START;
    // SAFETY: fstat on an arbitrary fd is safe; failure is reported as an error.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(format!("fd {fd} is not open: {}", std::io::Error::last_os_error()));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(format!("fd {fd} is not a socket"));
    }
    // Jobs must not inherit the listening socket.
    // SAFETY: fd is open (checked above).
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    // SAFETY: systemd handed us ownership of fd 3 and nothing else uses it.
    Ok(unsafe { UnixListener::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsing() {
        assert_eq!(parse_listen_env(7, Some("7"), Some("1")), Ok(1));
        assert_eq!(parse_listen_env(7, Some("7"), Some("3")), Ok(3));
        assert!(parse_listen_env(7, None, None).unwrap_err().contains("not set"));
        assert!(parse_listen_env(7, Some("8"), Some("1")).unwrap_err().contains("another process"));
        assert!(parse_listen_env(7, Some("7"), Some("0")).unwrap_err().contains("no socket"));
        assert!(parse_listen_env(7, Some("x"), Some("1")).is_err());
        assert!(parse_listen_env(7, Some("7"), Some("x")).is_err());
    }
}
