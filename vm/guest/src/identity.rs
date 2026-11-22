//! Resolving the run-as user (passwd lookups via libc).

use std::ffi::{CStr, CString};
use std::sync::Once;

#[derive(Debug, Clone)]
pub struct Identity {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    /// True when jobs must drop privileges to this user before exec.
    pub switch: bool,
}

struct Pw {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

/// # Safety
/// `pw` must come from a successful passwd lookup whose buffers are still alive.
unsafe fn pw_from(pw: &libc::passwd) -> Pw {
    let s = |p: *const libc::c_char| {
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    };
    Pw {
        name: s(pw.pw_name),
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        home: s(pw.pw_dir),
        shell: s(pw.pw_shell),
    }
}

fn lookup(
    f: impl Fn(*mut libc::passwd, *mut libc::c_char, usize, *mut *mut libc::passwd) -> libc::c_int,
) -> Option<Pw> {
    let mut size = 1024;
    loop {
        let mut buf = vec![0 as libc::c_char; size];
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = f(&mut pw, buf.as_mut_ptr(), buf.len(), &mut res);
        if rc == libc::ERANGE && size < 1 << 20 {
            size *= 4;
            continue;
        }
        if rc != 0 || res.is_null() {
            return None;
        }
        return Some(unsafe { pw_from(&pw) });
    }
}

fn by_name(name: &str) -> Option<Pw> {
    let c = CString::new(name).ok()?;
    lookup(|pw, buf, len, res| unsafe { libc::getpwnam_r(c.as_ptr(), pw, buf, len, res) })
}

fn by_uid(uid: u32) -> Option<Pw> {
    lookup(|pw, buf, len, res| unsafe { libc::getpwuid_r(uid, pw, buf, len, res) })
}

static WARN: Once = Once::new();

fn warn_once(msg: &str) {
    WARN.call_once(|| eprintln!("azula-guest: {msg}; running jobs as the worker's own user"));
}

/// Resolve who jobs run as. Falls back to the worker's own user (logging once)
/// when not root or when `run_as` doesn't exist.
pub fn resolve(run_as: &str) -> Identity {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        if let Some(pw) = by_name(run_as) {
            return Identity {
                name: pw.name,
                uid: pw.uid,
                gid: pw.gid,
                home: pw.home,
                shell: pw.shell,
                switch: true,
            };
        }
        warn_once(&format!("user {run_as:?} does not exist"));
    } else if by_name(run_as).is_none_or(|pw| pw.uid != euid) {
        // Started as `run_as` itself (systemd `User=`) is the normal
        // non-root setup and needs no warning.
        warn_once(&format!("not running as root, cannot switch to {run_as:?}"));
    }
    match by_uid(euid) {
        Some(pw) => Identity {
            name: pw.name,
            uid: pw.uid,
            gid: pw.gid,
            home: pw.home,
            shell: pw.shell,
            switch: false,
        },
        None => Identity {
            name: std::env::var("USER").unwrap_or_else(|_| euid.to_string()),
            uid: euid,
            gid: unsafe { libc::getegid() },
            home: std::env::var("HOME").unwrap_or_else(|_| "/".into()),
            shell: "/bin/sh".into(),
            switch: false,
        },
    }
}
