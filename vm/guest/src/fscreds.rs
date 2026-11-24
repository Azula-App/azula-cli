//! The job user's filesystem credentials, for put and get (vm/README.md 2.7, 2.8).
//!
//! A worker running as root must not touch a transfer's files as root: exec
//! children drop to the job user, and a transfer may reach no more than they
//! can. `AsUser` gives the calling thread a job's fsuid, fsgid, supplementary
//! groups and empty effective capabilities until it is dropped. The worker's
//! own files (the state dir) are root's, so it is held only around operations
//! on the target and its part file.
//!
//! Credentials belong to a thread in Linux, and each connection has its own.
//! Everything here is a raw syscall, because libc's setgroups (and the other
//! set*id wrappers) change every thread of the process.

use std::io;
use std::marker::PhantomData;

use crate::identity::Identity;

/// The calling thread acts on files as the job user while this lives.
#[must_use = "dropping it restores the worker's own credentials"]
pub struct AsUser {
    #[cfg(target_os = "linux")]
    prev: Option<sys::Creds>,
    /// Credentials are the thread's, so the guard must not leave it.
    _not_send: PhantomData<*const ()>,
}

impl AsUser {
    /// Switch this thread to `id`, or do nothing when the worker already runs
    /// as that user. On an error the thread is back as it was, and the caller
    /// must not go on to the file.
    pub fn enter(id: &Identity) -> io::Result<AsUser> {
        if !id.switch || id.uid == unsafe { libc::geteuid() } {
            return Ok(AsUser {
                #[cfg(target_os = "linux")]
                prev: None,
                _not_send: PhantomData,
            });
        }
        Self::switch(id)
            .map_err(|e| io::Error::new(e.kind(), format!("cannot act as user {}: {e}", id.name)))
    }

    #[cfg(target_os = "linux")]
    fn switch(id: &Identity) -> io::Result<AsUser> {
        let prev = sys::Creds::current()?;
        let want = sys::Creds::of_job(id, &prev)?;
        // From here on the guard puts `prev` back, whatever fails.
        let guard = AsUser {
            prev: Some(prev),
            _not_send: PhantomData,
        };
        want.set()?;
        Ok(guard)
    }

    #[cfg(not(target_os = "linux"))]
    fn switch(_: &Identity) -> io::Result<AsUser> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(target_os = "linux")]
impl Drop for AsUser {
    fn drop(&mut self) {
        // The worker may always go back to its own credentials. If that ever
        // failed, this thread could not go on as either user, so end it.
        if let Some(Err(e)) = self.prev.as_ref().map(sys::Creds::set) {
            panic!("cannot restore the worker's credentials: {e}");
        }
    }
}

/// 64-bit Linux ABIs; the 32-bit ones number the 32-bit-id calls differently.
#[cfg(target_os = "linux")]
mod sys {
    use std::ffi::CString;
    use std::io;

    use libc::{c_int, c_long};

    use crate::identity::Identity;

    /// No id: setfsuid and setfsgid change nothing and return the current one.
    const NO_ID: c_long = -1;

    /// `__user_cap_data_struct[2]`.
    type Caps = [[u32; 3]; 2];
    const EFFECTIVE: usize = 0;
    const PERMITTED: usize = 1;

    /// One thread's filesystem credentials.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Creds {
        uid: u32,
        gid: u32,
        /// Sorted, as the kernel keeps them.
        groups: Vec<u32>,
        caps: Caps,
    }

    impl Creds {
        pub fn current() -> io::Result<Creds> {
            let mut caps = Caps::default();
            cap_call(libc::SYS_capget, &mut caps)?;
            Ok(Creds {
                uid: unsafe { libc::syscall(libc::SYS_setfsuid, NO_ID) } as u32,
                gid: unsafe { libc::syscall(libc::SYS_setfsgid, NO_ID) } as u32,
                groups: current_groups()?,
                caps,
            })
        }

        /// What a job of `id` gets from initgroups, setgid and setuid. No
        /// effective capabilities: fsuid alone drops only the file ones, which
        /// leaves CAP_SYS_PTRACE (other processes' /proc/N/root), for example.
        pub fn of_job(id: &Identity, now: &Creds) -> io::Result<Creds> {
            let mut caps = now.caps;
            for c in &mut caps {
                c[EFFECTIVE] = 0;
            }
            Ok(Creds {
                uid: id.uid,
                gid: id.gid,
                groups: groups_of(&id.name, id.gid)?,
                caps,
            })
        }

        /// Make this the calling thread's credentials, and check that it is.
        pub fn set(&self) -> io::Result<()> {
            let now = Creds::current()?;
            if now == *self {
                return Ok(());
            }
            // Changing ids needs CAP_SETUID and CAP_SETGID, which are
            // permitted but not effective while acting as the job user.
            let mut all = self.caps;
            for c in &mut all {
                c[EFFECTIVE] = c[PERMITTED];
            }
            cap_call(libc::SYS_capset, &mut all)?;
            if now.groups != self.groups {
                check(unsafe {
                    libc::syscall(
                        libc::SYS_setgroups,
                        self.groups.len() as c_long,
                        self.groups.as_ptr(),
                    )
                })?;
            }
            unsafe {
                libc::syscall(libc::SYS_setfsgid, self.gid as c_long);
                libc::syscall(libc::SYS_setfsuid, self.uid as c_long);
            }
            // Last: moving fsuid to or from 0 adjusts the effective set.
            let mut caps = self.caps;
            cap_call(libc::SYS_capset, &mut caps)?;
            // setfsuid and setfsgid report no errors, so ask the kernel.
            if Creds::current()? != *self {
                return Err(io::Error::other("the kernel refused the credentials"));
            }
            Ok(())
        }
    }

    fn check(ret: c_long) -> io::Result<usize> {
        usize::try_from(ret).map_err(|_| io::Error::last_os_error())
    }

    /// capget or capset on the calling thread.
    fn cap_call(nr: c_long, caps: &mut Caps) -> io::Result<()> {
        // `__user_cap_header_struct`: version 3, then pid 0 for this thread.
        let mut header = [0x2008_0522u32, 0];
        check(unsafe { libc::syscall(nr, header.as_mut_ptr(), caps.as_mut_ptr()) }).map(|_| ())
    }

    fn current_groups() -> io::Result<Vec<u32>> {
        let none = std::ptr::null_mut::<u32>();
        let n = check(unsafe { libc::syscall(libc::SYS_getgroups, 0 as c_long, none) })?;
        let mut groups = vec![0u32; n];
        let n =
            check(unsafe { libc::syscall(libc::SYS_getgroups, n as c_long, groups.as_mut_ptr()) })?;
        groups.truncate(n);
        groups.sort_unstable();
        Ok(groups)
    }

    /// The groups initgroups would set.
    fn groups_of(user: &str, gid: u32) -> io::Result<Vec<u32>> {
        let user = CString::new(user)?;
        let mut groups = vec![0u32; 64];
        loop {
            let room = groups.len();
            let mut n = room as c_int;
            let ret =
                unsafe { libc::getgrouplist(user.as_ptr(), gid, groups.as_mut_ptr(), &mut n) };
            let n = usize::try_from(n).unwrap_or(0);
            if ret >= 0 {
                groups.truncate(n);
                groups.sort_unstable();
                return Ok(groups);
            }
            // -1 with a larger count means the list did not fit.
            if n <= room {
                return Err(io::Error::other("cannot read the user's groups"));
            }
            groups.resize(n, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me(switch: bool) -> Identity {
        Identity {
            name: "me".into(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            home: "/".into(),
            shell: "/bin/sh".into(),
            switch,
        }
    }

    #[test]
    fn nothing_to_do_as_the_worker_itself() {
        assert!(AsUser::enter(&me(false)).is_ok());
        // `--run-as root` under a root worker: no other user to become.
        assert!(AsUser::enter(&me(true)).is_ok());
    }

    /// A switch that can't happen is an error, never a fallback to the worker's
    /// credentials: not permitted on Linux, not possible elsewhere.
    #[test]
    fn a_refused_switch_is_an_error() {
        if unsafe { libc::geteuid() } == 0 {
            return; // tests/run_as.rs has root's version
        }
        let mut other = me(true);
        other.uid += 1;
        let e = AsUser::enter(&other).err().expect("must not succeed");
        assert!(e.to_string().starts_with("cannot act as user me: "), "{e}");
        // ... and leaves this thread able to use its own files.
        let p = std::env::temp_dir().join(format!("azula-fscreds-{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        std::fs::remove_file(&p).unwrap();
    }
}
