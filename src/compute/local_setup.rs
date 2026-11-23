//! `azula compute local-setup` (Linux): one-time, root-only, idempotent setup
//! of the local backend's Terminal mode (`vm/BROKER.md` §9). It creates the
//! unprivileged job user, installs `azula-guest`, and writes and enables the
//! systemd units: `azula-guest.socket` (a socket only the invoking user can
//! open), `azula-guest.service` (the worker, as the job user) and
//! `azula-compute.service` (the broker, as the invoking user).
//!
//! The unit-file rendering and the write-if-changed logic are pure and
//! unit-tested on every platform; only [`run`] touches the system.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::path::Path;

use super::local::{UserDb, UserEntry, DEFAULT_WORKER_SOCKET};

pub const GUEST_INSTALL_DIR: &str = "/usr/local/lib/azula";
pub const GUEST_INSTALL_PATH: &str = "/usr/local/lib/azula/azula-guest";
pub const STATE_DIR: &str = "/var/lib/azula-guest";
pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const SOCKET_UNIT: &str = "azula-guest.socket";
pub const GUEST_UNIT: &str = "azula-guest.service";
pub const COMPUTE_UNIT: &str = "azula-compute.service";

/// `MemoryMax` for the worker: total memory minus 1 GiB, never below 256 MiB,
/// so job page cache can't push the VM's footprint into the host's
/// low-memory killer (task 1.9).
pub fn memory_max_mb(mem_total_mb: u64) -> u64 {
    mem_total_mb.saturating_sub(1024).max(256)
}

/// Quote one argument for a systemd `ExecStart=` line.
fn exec_arg(a: &str) -> String {
    let a = a.replace('%', "%%");
    if a.chars().any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\')) {
        format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        a
    }
}

/// A user name safe to put after `User=`/`SocketUser=`.
fn valid_unit_user(u: &str) -> bool {
    !u.is_empty() && !u.starts_with('-') && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub fn render_socket_unit(broker_user: &str) -> String {
    format!(
        "[Unit]\n\
         Description=azula compute worker socket (only {broker_user} can connect)\n\
         \n\
         [Socket]\n\
         ListenStream={DEFAULT_WORKER_SOCKET}\n\
         SocketUser={broker_user}\n\
         SocketMode=0600\n\
         DirectoryMode=0700\n\
         # /run/azula must be traversable by the broker user.\n\
         ExecStartPre=/usr/bin/install -d -o {broker_user} -m 0700 /run/azula\n\
         \n\
         [Install]\n\
         WantedBy=sockets.target\n"
    )
}

pub fn render_guest_service(job_user: &str, memory_max_mb: u64) -> String {
    format!(
        "[Unit]\n\
         Description=azula compute worker (runs jobs as {job_user})\n\
         Requires={SOCKET_UNIT}\n\
         After={SOCKET_UNIT}\n\
         \n\
         [Service]\n\
         User={job_user}\n\
         ExecStart={GUEST_INSTALL_PATH} --systemd-socket --run-as {job_user} --state-dir {STATE_DIR}\n\
         MemoryMax={memory_max_mb}M\n\
         Restart=on-failure\n"
    )
}

pub fn render_compute_service(broker_user: &str, exe: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=azula compute broker\n\
         Wants=network-online.target\n\
         After=network-online.target {SOCKET_UNIT}\n\
         Requires={SOCKET_UNIT}\n\
         \n\
         [Service]\n\
         User={broker_user}\n\
         ExecStart={} compute serve --local\n\
         Restart=always\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exec_arg(&exe.to_string_lossy())
    )
}

/// Write `content` to `path` (atomically, with `mode`) unless it already has
/// exactly that content and mode. Returns whether it changed anything.
pub fn write_if_changed(path: &Path, content: &[u8], mode: u32) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    if let (Ok(old), Ok(meta)) = (std::fs::read(path), std::fs::metadata(path)) {
        if old == content && meta.permissions().mode() & 0o7777 == mode {
            return Ok(false);
        }
    }
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    std::fs::create_dir_all(dir)?;
    // A temp file + rename, so replacing a running binary doesn't hit ETXTBSY.
    let tmp = dir.join(format!(".{}.tmp{}", path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(), std::process::id()));
    std::fs::write(&tmp, content)?;
    let finish = || -> io::Result<()> {
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, path)
    };
    finish().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(true)
}

/// Who `local-setup` sets the broker up for: `$SUDO_USER`, which must exist
/// and not be root; and the caller must be root.
pub fn resolve_invoker(euid: u32, sudo_user: Option<&str>, db: &dyn UserDb) -> Result<(String, UserEntry), String> {
    if euid != 0 {
        return Err("`azula compute local-setup` must run as root, through sudo: `sudo azula compute local-setup`".into());
    }
    let Some(user) = sudo_user.filter(|u| !u.is_empty() && *u != "root") else {
        return Err("run it through sudo from your own user (`sudo azula compute local-setup`): SUDO_USER is unset or root, \
                    and the broker must run as a normal user, not root"
            .into());
    };
    if !valid_unit_user(user) {
        return Err(format!("SUDO_USER `{user}` is not a usable user name"));
    }
    let entry = db.user(user).ok_or_else(|| format!("SUDO_USER `{user}` does not exist"))?;
    if entry.uid == 0 {
        return Err(format!("SUDO_USER `{user}` has uid 0; the broker must run as a normal user"));
    }
    Ok((user.to_owned(), entry))
}

#[cfg(target_os = "linux")]
pub use sys::run;

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::compute::local::{check_job_user, find_guest_bin, parse_mem_total_mb, SystemDb, DEFAULT_RUN_AS};
    use anyhow::{anyhow, bail, Context, Result};
    use std::process::Command;

    fn cmd(prog: &str, args: &[&str]) -> Result<()> {
        let st = Command::new(prog).args(args).status().with_context(|| format!("running {prog}"))?;
        if !st.success() {
            bail!("`{prog} {}` failed ({st})", args.join(" "));
        }
        Ok(())
    }

    fn report(what: &str, changed: bool) {
        crate::outln!("  {} {what}", if changed { "updated  " } else { "unchanged" });
    }

    /// Run the whole setup. Safe to run again: unchanged files are left alone.
    pub fn run() -> Result<()> {
        let db = SystemDb;
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        let sudo_user = std::env::var("SUDO_USER").ok();
        let (broker_user, broker) = resolve_invoker(euid, sudo_user.as_deref(), &db).map_err(|e| anyhow!(e))?;
        let job_user = DEFAULT_RUN_AS;
        let exe = std::env::current_exe().context("locating this executable")?.canonicalize().context("resolving this executable's path")?;
        let guest_src = find_guest_bin().map_err(|e| anyhow!(e))?;
        let mem_mb = std::fs::read_to_string("/proc/meminfo").ok().and_then(|t| parse_mem_total_mb(&t)).ok_or_else(|| anyhow!("cannot read MemTotal from /proc/meminfo"))?;

        crate::outln!("azula compute local-setup: broker user `{broker_user}`, job user `{job_user}`");

        // 1. The job user.
        if db.user(job_user).is_none() {
            cmd("useradd", &["-m", "-s", "/bin/bash", job_user])?;
            crate::outln!("  created   user {job_user}");
        } else {
            crate::outln!("  unchanged user {job_user}");
        }
        // Never leave a job user that could escape: same checks as `serve --local`.
        check_job_user(&db, job_user, broker.uid).map_err(|e| anyhow!(e))?;
        let job = db.user(job_user).ok_or_else(|| anyhow!("user {job_user} vanished"))?;

        // 2. The worker binary and its state directory.
        let bytes = std::fs::read(&guest_src).with_context(|| format!("reading {}", guest_src.display()))?;
        report(GUEST_INSTALL_PATH, write_if_changed(Path::new(GUEST_INSTALL_PATH), &bytes, 0o755).with_context(|| format!("installing {GUEST_INSTALL_PATH}"))?);
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::create_dir_all(STATE_DIR).with_context(|| format!("creating {STATE_DIR}"))?;
            std::os::unix::fs::chown(STATE_DIR, Some(job.uid), Some(job.gid)).with_context(|| format!("chown {STATE_DIR}"))?;
            std::fs::set_permissions(STATE_DIR, std::fs::Permissions::from_mode(0o700)).with_context(|| format!("chmod {STATE_DIR}"))?;
            crate::outln!("  ensured   {STATE_DIR} ({job_user}, 0700)");
        }

        // 3. The units.
        let units = [
            (SOCKET_UNIT, render_socket_unit(&broker_user)),
            (GUEST_UNIT, render_guest_service(job_user, memory_max_mb(mem_mb))),
            (COMPUTE_UNIT, render_compute_service(&broker_user, &exe)),
        ];
        let mut changed = false;
        for (name, text) in &units {
            let path = Path::new(UNIT_DIR).join(name);
            let c = write_if_changed(&path, text.as_bytes(), 0o644).with_context(|| format!("writing {}", path.display()))?;
            report(&path.to_string_lossy(), c);
            changed |= c;
        }
        if changed {
            cmd("systemctl", &["daemon-reload"])?;
        }
        cmd("systemctl", &["enable", "--now", SOCKET_UNIT, COMPUTE_UNIT])?;
        if changed {
            crate::outln!("  note: changed units apply to running services when they restart (`sudo systemctl restart {COMPUTE_UNIT}`; restarting {GUEST_UNIT} ends running jobs)");
        }

        crate::outln!("");
        crate::outln!("Done. The broker is running as `{broker_user}`; jobs run as `{job_user}` (no sudo).");
        crate::outln!("Next, as `{broker_user}` (not root), mint a token for a client:");
        crate::outln!("  azula compute grant --label \"my cloud session\"");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Db(HashMap<String, UserEntry>);
    impl UserDb for Db {
        fn user(&self, name: &str) -> Option<UserEntry> {
            self.0.get(name).cloned()
        }
        fn group(&self, _: &str) -> Option<(u32, Vec<String>)> {
            None
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("azula-setup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn memory_max_leaves_a_gib() {
        assert_eq!(memory_max_mb(4096), 3072);
        assert_eq!(memory_max_mb(5300), 4276);
        assert_eq!(memory_max_mb(1024), 256);
        assert_eq!(memory_max_mb(100), 256);
    }

    #[test]
    fn socket_unit_text() {
        let u = render_socket_unit("droid");
        assert!(u.contains("ListenStream=/run/azula/worker.sock\n"));
        assert!(u.contains("SocketUser=droid\n"));
        assert!(u.contains("SocketMode=0600\n"));
        assert!(u.contains("DirectoryMode=0700\n"));
        assert!(u.contains("ExecStartPre=/usr/bin/install -d -o droid -m 0700 /run/azula\n"));
        assert!(u.contains("WantedBy=sockets.target"));
    }

    #[test]
    fn guest_service_text() {
        let u = render_guest_service("azula", 3072);
        assert!(u.contains("User=azula\n"));
        assert!(u.contains("ExecStart=/usr/local/lib/azula/azula-guest --systemd-socket --run-as azula --state-dir /var/lib/azula-guest\n"));
        assert!(u.contains("MemoryMax=3072M\n"));
        assert!(u.contains("Requires=azula-guest.socket\n"));
        assert!(!u.contains("[Install]"), "socket activation starts it; it is not enabled itself");
    }

    #[test]
    fn compute_service_text_and_quoting() {
        let u = render_compute_service("droid", Path::new("/home/droid/azula"));
        assert!(u.contains("User=droid\n"));
        assert!(u.contains("ExecStart=/home/droid/azula compute serve --local\n"));
        assert!(u.contains("Restart=always\n"));
        assert!(u.contains("Requires=azula-guest.socket\n"));
        assert!(u.contains("WantedBy=multi-user.target"));
        let q = render_compute_service("droid", Path::new("/home/d d/azula%1"));
        assert!(q.contains("ExecStart=\"/home/d d/azula%%1\" compute serve --local\n"), "{q}");
    }

    #[test]
    fn invoker_checks() {
        let mut m = HashMap::new();
        m.insert("droid".to_owned(), UserEntry { uid: 1000, gid: 1000 });
        m.insert("rootish".to_owned(), UserEntry { uid: 0, gid: 0 });
        let db = Db(m);
        assert!(resolve_invoker(1000, Some("droid"), &db).unwrap_err().contains("as root"));
        assert!(resolve_invoker(0, None, &db).unwrap_err().contains("SUDO_USER"));
        assert!(resolve_invoker(0, Some("root"), &db).unwrap_err().contains("SUDO_USER"));
        assert!(resolve_invoker(0, Some(""), &db).unwrap_err().contains("SUDO_USER"));
        assert!(resolve_invoker(0, Some("ghost"), &db).unwrap_err().contains("does not exist"));
        assert!(resolve_invoker(0, Some("rootish"), &db).unwrap_err().contains("uid 0"));
        assert!(resolve_invoker(0, Some("a b"), &db).unwrap_err().contains("usable"));
        assert_eq!(resolve_invoker(0, Some("droid"), &db).unwrap(), ("droid".to_owned(), UserEntry { uid: 1000, gid: 1000 }));
    }

    #[test]
    fn write_if_changed_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("wic");
        let p = d.join("sub/a.unit");
        assert!(write_if_changed(&p, b"one", 0o644).unwrap(), "creates");
        assert!(!write_if_changed(&p, b"one", 0o644).unwrap(), "same content and mode: no write");
        let t0 = std::fs::metadata(&p).unwrap().modified().unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), t0);
        assert!(write_if_changed(&p, b"two", 0o644).unwrap(), "new content");
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(write_if_changed(&p, b"two", 0o755).unwrap(), "new mode");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o755);
        let leftovers: Vec<_> = std::fs::read_dir(p.parent().unwrap()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(leftovers.len(), 1, "no temp files left: {leftovers:?}");
        let _ = std::fs::remove_dir_all(d);
    }
}
