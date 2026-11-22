//! `azula compute push|pull`: resumable single-file transfer to and from the
//! VM's filesystem (`vm/README.md` §2.7/§2.8, `vm/BROKER.md` §7), and
//! directory trees (`-r`) as tar streamed through exec.
//!
//! Resume works within an invocation (a dropped connection continues from the
//! guest's part-file offset / our part file's length) and across invocations
//! via `transfers.json` in the compute directory. SHA-256 is computed while
//! streaming at both ends, nothing is renamed into place until size and
//! digest match, and a changed local or remote file restarts from zero.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::client::{run_job, Dialer, Event, ExecRequest, Failure, Outcome, Policy, Session, Start};
use super::frame::{read_frame, write_frame, Frame, MAX_PAYLOAD};
use super::grants::write_private_atomic;

/// Largest data frame we send (the contract allows 1 MiB).
const CHUNK: usize = 512 * 1024;

/// Error codes that describe a problem with the file, not the broker.
const FILE_CODES: &[&str] = &["not_found", "not_a_file", "exists", "is_a_directory", "not_a_directory", "changed", "size_mismatch", "digest_mismatch", "io_error", "upload_conflict"];

/// Why a transfer failed.
#[derive(Debug, Clone, PartialEq)]
pub enum TransferError {
    /// A file problem from either end (exit 1).
    File { code: String, msg: String },
    /// A broker error such as `unauthorized` or `vm_not_running` (exit 125).
    Broker { code: String, msg: String },
    /// The connection failed past the reconnect window (exit 255).
    Transport(String),
}

impl TransferError {
    pub fn exit_code(&self) -> i32 {
        match self {
            TransferError::File { .. } => 1,
            TransferError::Broker { .. } => 125,
            TransferError::Transport(_) => 255,
        }
    }

    pub fn message(&self) -> String {
        match self {
            TransferError::File { code, msg } | TransferError::Broker { code, msg } => format!("{code}: {msg}"),
            TransferError::Transport(m) => m.clone(),
        }
    }

    fn file(code: &str, msg: impl Into<String>) -> Self {
        TransferError::File { code: code.into(), msg: msg.into() }
    }

    fn from_frame(f: &Frame) -> Self {
        let code = f.str_field("code").unwrap_or("internal").to_owned();
        let msg = f.str_field("msg").unwrap_or("").to_owned();
        if FILE_CODES.contains(&code.as_str()) {
            TransferError::File { code, msg }
        } else {
            TransferError::Broker { code, msg }
        }
    }
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for TransferError {}

impl From<Failure> for TransferError {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Broker { code, msg } => TransferError::Broker { code, msg },
            Failure::Transport(m) => TransferError::Transport(m),
        }
    }
}

/// The result printed by `push`/`pull --json`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Transfer {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub resumed_from: u64,
}

// --- transfers.json -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    size: u64,
    mtime_ns: u128,
    /// Push: the upload id. Pull: the part-file id.
    id: String,
    /// Pull: the remote file's etag.
    etag: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    transfers: BTreeMap<String, Record>,
}

/// `~/.azula/compute/transfers.json`: what an interrupted transfer needs to continue.
#[derive(Debug, Clone)]
pub struct TransferStore {
    path: PathBuf,
}

impl TransferStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The default location under the compute directory.
    pub fn default_location() -> Self {
        Self::new(super::compute_dir().join("transfers.json"))
    }

    fn load(&self) -> StoreFile {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, f: &StoreFile) {
        if let Some(dir) = self.path.parent() {
            let _ = super::grants::create_private_dir(dir);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(f) {
            let _ = write_private_atomic(&self.path, &bytes);
        }
    }

    fn get(&self, key: &str) -> Option<Record> {
        self.load().transfers.get(key).cloned()
    }

    fn put(&self, key: &str, rec: Record) {
        let mut f = self.load();
        f.transfers.insert(key.to_owned(), rec);
        self.save(&f);
    }

    fn remove(&self, key: &str) {
        let mut f = self.load();
        if f.transfers.remove(key).is_some() {
            self.save(&f);
        }
    }

    /// Number of recorded transfers (tests, diagnostics).
    pub fn len(&self) -> usize {
        self.load().transfers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// --- helpers --------------------------------------------------------------------

/// Reconnect bookkeeping shared by push and pull.
struct Outage {
    since: Option<Instant>,
    attempt: u32,
}

impl Outage {
    fn new() -> Self {
        Outage { since: None, attempt: 0 }
    }

    /// Say once per outage that we are about to resume (stderr), like exec's
    /// "connection lost, reattaching" line.
    fn notice(&self, policy: &Policy, verb: &str, at: u64) {
        if self.since.is_none() && !policy.window.is_zero() {
            eprintln!("{}", resume_notice(verb, at));
        }
    }

    fn reset(&mut self) {
        self.since = None;
        self.attempt = 0;
    }

    /// Sleep before the next attempt, or fail once the window is spent.
    async fn wait(&mut self, policy: &Policy, why: &str) -> Result<(), TransferError> {
        if policy.window.is_zero() {
            return Err(TransferError::Transport(format!("connection to the host failed: {why}")));
        }
        let since = *self.since.get_or_insert_with(Instant::now);
        let elapsed = since.elapsed();
        if elapsed >= policy.window {
            return Err(TransferError::Transport(format!("lost the connection and could not reconnect within {}s: {why}", policy.window.as_secs())));
        }
        self.attempt += 1;
        let wait = policy_backoff(policy, self.attempt).min(policy.window - elapsed);
        tokio::time::sleep(wait).await;
        Ok(())
    }
}

fn policy_backoff(p: &Policy, attempt: u32) -> Duration {
    p.initial.saturating_mul(1u32 << attempt.saturating_sub(1).min(10)).min(p.max)
}

/// `azula: connection lost, resuming push at 2.9 MiB`.
pub fn resume_notice(verb: &str, at: u64) -> String {
    format!("azula: connection lost, resuming {verb} at {}", human_bytes(at))
}

/// Bytes as `1.5 KiB` / `512 B`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

fn basename(p: &str) -> Option<&str> {
    p.trim_end_matches('/').rsplit('/').next().filter(|s| !s.is_empty() && *s != "." && *s != "..")
}

async fn hash_file(path: &Path, upto: Option<u64>) -> std::io::Result<Sha256> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut h = Sha256::new();
    let mut remaining = upto.unwrap_or(u64::MAX);
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let want = (buf.len() as u64).min(remaining) as usize;
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(h)
}

fn mtime_ns(meta: &std::fs::Metadata) -> u128 {
    meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0)
}

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_: &std::fs::Metadata) -> u32 {
    0o644
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777));
}

#[cfg(not(unix))]
fn set_file_mode(_: &Path, _: u32) {}

async fn read_reply(s: &mut Session) -> Result<Frame, String> {
    match read_frame(&mut s.recv).await {
        Ok(Some(f)) => Ok(f),
        Ok(None) => Err("the connection closed".to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

// --- push -----------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct PushOptions {
    pub vm: Option<String>,
    /// Default: the local file's mode.
    pub mode: Option<u32>,
    pub no_clobber: bool,
    pub policy: Policy,
}

enum PushStep {
    Done(Transfer),
    /// Start over with a fresh upload id (the id was taken, or the offset was bogus).
    NewUpload,
    /// The target is a directory: append the source's basename and go again.
    IntoDirectory,
    /// The worker discarded a bad part file; try again from zero.
    Restart(TransferError),
    Dropped(String),
    Fail(TransferError),
}

/// Copy one local file (or stdin, for `-`) to `remote` in the VM.
pub async fn push(
    dialer: &Dialer,
    store: &TransferStore,
    local: &str,
    remote: &str,
    opts: &PushOptions,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Transfer, TransferError> {
    if local == "-" {
        return push_stdin(dialer, remote, opts).await;
    }
    let meta = tokio::fs::metadata(local).await.map_err(|e| TransferError::file("not_found", format!("{local}: {e}")))?;
    if meta.is_dir() {
        return Err(TransferError::file("not_a_file", format!("{local} is a directory; use -r to copy a directory tree")));
    }
    let size = meta.len();
    let mtime = mtime_ns(&meta);
    let mode = opts.mode.unwrap_or_else(|| file_mode(&meta));
    let digest = hex(hash_file(Path::new(local), None).await.map_err(|e| TransferError::file("io_error", format!("{local}: {e}")))?.finalize().as_slice());

    let mut remote_path = remote.to_owned();
    if remote_path.ends_with('/') {
        let name = basename(local).ok_or_else(|| TransferError::file("bad_request", "cannot derive a file name from the local path"))?;
        remote_path.push_str(name);
    }
    let abs_local = std::fs::canonicalize(local).unwrap_or_else(|_| PathBuf::from(local));

    let mut session = dialer.session().await?;
    let vm = session.resolve_vm(opts.vm.as_deref());
    let host = session.host();
    let mut outage = Outage::new();
    let mut restarts = 0u32;
    let mut first_offset: Option<u64> = None;
    let pos = std::cell::Cell::new(0u64);
    let mut tracked = |d: u64, t: u64| {
        pos.set(d);
        progress(d, t);
    };
    let mut appended_dir = false;

    loop {
        let key = format!("push|{host}|{vm}|{}|{remote_path}", abs_local.display());
        let rec = match store.get(&key).filter(|r| r.size == size && r.mtime_ns == mtime) {
            Some(r) => r,
            None => {
                let r = Record { size, mtime_ns: mtime, id: uuid::Uuid::new_v4().to_string(), etag: None };
                store.put(&key, r.clone());
                r
            }
        };
        let step = push_once(&mut session, &vm, &remote_path, &rec.id, mode, !opts.no_clobber, local, size, &digest, dialer, &mut tracked, &mut first_offset).await;
        session.conn.close(0u32.into(), b"done");
        match step {
            PushStep::Done(mut t) => {
                // The local file must not have changed under us.
                let after = tokio::fs::metadata(local).await.ok();
                if after.as_ref().is_some_and(|m| m.len() != size || mtime_ns(m) != mtime) {
                    return Err(TransferError::file("changed", "the local file changed while it was being sent; run the push again"));
                }
                store.remove(&key);
                t.resumed_from = first_offset.unwrap_or(0);
                return Ok(t);
            }
            PushStep::IntoDirectory if !appended_dir => {
                appended_dir = true;
                let name = basename(local).ok_or_else(|| TransferError::file("is_a_directory", "the remote path is a directory"))?;
                store.remove(&key);
                remote_path = format!("{}/{name}", remote_path.trim_end_matches('/'));
            }
            PushStep::IntoDirectory => return Err(TransferError::file("is_a_directory", format!("{remote_path} is a directory"))),
            PushStep::NewUpload | PushStep::Restart(_) if restarts < 3 => {
                restarts += 1;
                if matches!(step, PushStep::NewUpload) {
                    store.remove(&key);
                }
            }
            PushStep::NewUpload => return Err(TransferError::file("upload_conflict", "could not start a fresh upload")),
            PushStep::Restart(e) => return Err(e),
            PushStep::Fail(e) => {
                if matches!(&e, TransferError::File { .. }) {
                    // A file error ends this transfer; don't leave a resumable record behind for it.
                    store.remove(&key);
                }
                return Err(e);
            }
            PushStep::Dropped(why) => {
                outage.notice(&opts.policy, "push", pos.get());
                outage.wait(&opts.policy, &why).await?;
                loop {
                    match dialer.session().await {
                        Ok(s) => {
                            session = s;
                            break;
                        }
                        Err(Failure::Transport(m)) => outage.wait(&opts.policy, &m).await?,
                        Err(f) => return Err(f.into()),
                    }
                }
                outage.reset();
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn push_once(
    s: &mut Session,
    vm: &str,
    remote: &str,
    upload: &str,
    mode: u32,
    overwrite: bool,
    local: &str,
    size: u64,
    digest: &str,
    dialer: &Dialer,
    progress: &mut dyn FnMut(u64, u64),
    first_offset: &mut Option<u64>,
) -> PushStep {
    let req = Frame::new(json!({
        "t": "put", "vm": vm, "start": true, "path": remote, "upload": upload,
        "mode": mode, "overwrite": overwrite, "mkdirs": true,
    }));
    if let Err(e) = write_frame(&mut s.send, &req).await {
        return PushStep::Dropped(e.to_string());
    }
    let ready = match read_reply(s).await {
        Ok(f) => f,
        Err(e) => return PushStep::Dropped(e),
    };
    match ready.t() {
        "put_ready" => {}
        "error" => {
            return match ready.str_field("code") {
                Some("is_a_directory") => PushStep::IntoDirectory,
                Some("upload_conflict") => PushStep::NewUpload,
                Some("size_mismatch") | Some("digest_mismatch") => PushStep::Restart(TransferError::from_frame(&ready)),
                _ => PushStep::Fail(TransferError::from_frame(&ready)),
            }
        }
        other => return PushStep::Fail(TransferError::Broker { code: "internal".into(), msg: format!("unexpected `{other}` frame") }),
    }
    let offset = ready.header.get("offset").and_then(Value::as_u64).unwrap_or(0);
    *first_offset = Some(offset);
    if offset > size {
        return PushStep::NewUpload;
    }
    let mut f = match tokio::fs::File::open(local).await {
        Ok(f) => f,
        Err(e) => return PushStep::Fail(TransferError::file("io_error", format!("{local}: {e}"))),
    };
    if f.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
        return PushStep::Fail(TransferError::file("io_error", format!("{local}: cannot seek")));
    }
    let mut sent = offset;
    let mut buf = vec![0u8; CHUNK.min(MAX_PAYLOAD)];
    while sent < size {
        let want = (buf.len() as u64).min(size - sent) as usize;
        let n = match f.read(&mut buf[..want]).await {
            Ok(0) => return PushStep::Fail(TransferError::file("changed", "the local file shrank while it was being sent")),
            Ok(n) => n,
            Err(e) => return PushStep::Fail(TransferError::file("io_error", format!("{local}: {e}"))),
        };
        if let Err(e) = write_frame(&mut s.send, &Frame::with_payload(json!({"t": "data"}), buf[..n].to_vec())).await {
            return PushStep::Dropped(e.to_string());
        }
        sent += n as u64;
        progress(sent, size);
        if dialer.fault.as_ref().is_some_and(|fl| fl.bytes(n as u64)) {
            // Let what was just written reach the guest first, so a test of resume
            // is deterministic; a real outage would not wait.
            tokio::time::sleep(Duration::from_millis(150)).await;
            s.conn.close(0u32.into(), b"fault injection");
            return PushStep::Dropped("fault injected".into());
        }
    }
    if let Err(e) = write_frame(&mut s.send, &Frame::new(json!({"t": "eof", "size": size, "sha256": digest}))).await {
        return PushStep::Dropped(e.to_string());
    }
    match read_reply(s).await {
        Ok(f) if f.t() == "put_ok" => {
            let got_size = f.header.get("size").and_then(Value::as_u64).unwrap_or(size);
            let got_sha = f.str_field("sha256").unwrap_or(digest);
            if got_size != size || got_sha != digest {
                return PushStep::Fail(TransferError::file("digest_mismatch", "the worker's confirmation does not match what was sent"));
            }
            PushStep::Done(Transfer { path: f.str_field("path").unwrap_or(remote).to_owned(), size, sha256: digest.to_owned(), resumed_from: 0 })
        }
        Ok(f) if f.t() == "error" => match f.str_field("code") {
            Some("size_mismatch") | Some("digest_mismatch") => PushStep::Restart(TransferError::from_frame(&f)),
            _ => PushStep::Fail(TransferError::from_frame(&f)),
        },
        Ok(f) => PushStep::Fail(TransferError::Broker { code: "internal".into(), msg: format!("unexpected `{}` frame", f.t()) }),
        Err(e) => PushStep::Dropped(e),
    }
}

/// `push - REMOTE`: stream stdin, single attempt (not resumable).
async fn push_stdin(dialer: &Dialer, remote: &str, opts: &PushOptions) -> Result<Transfer, TransferError> {
    if remote.ends_with('/') {
        return Err(TransferError::file("bad_request", "pushing stdin needs a full remote file name, not a directory"));
    }
    let mut s = dialer.session().await?;
    let vm = s.resolve_vm(opts.vm.as_deref());
    let req = Frame::new(json!({
        "t": "put", "vm": vm, "start": true, "path": remote, "upload": uuid::Uuid::new_v4().to_string(),
        "mode": opts.mode.unwrap_or(0o644), "overwrite": !opts.no_clobber, "mkdirs": true,
    }));
    write_frame(&mut s.send, &req).await.map_err(|e| TransferError::Transport(e.to_string()))?;
    let ready = read_reply(&mut s).await.map_err(TransferError::Transport)?;
    if ready.t() == "error" {
        return Err(TransferError::from_frame(&ready));
    }
    let mut stdin = tokio::io::stdin();
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = stdin.read(&mut buf).await.map_err(|e| TransferError::file("io_error", format!("stdin: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
        write_frame(&mut s.send, &Frame::with_payload(json!({"t": "data"}), buf[..n].to_vec())).await.map_err(|e| TransferError::Transport(e.to_string()))?;
    }
    let digest = hex(hasher.finalize().as_slice());
    write_frame(&mut s.send, &Frame::new(json!({"t": "eof", "size": total, "sha256": digest}))).await.map_err(|e| TransferError::Transport(e.to_string()))?;
    let done = read_reply(&mut s).await.map_err(TransferError::Transport)?;
    s.conn.close(0u32.into(), b"done");
    match done.t() {
        "put_ok" => Ok(Transfer { path: done.str_field("path").unwrap_or(remote).to_owned(), size: total, sha256: digest, resumed_from: 0 }),
        _ => Err(TransferError::from_frame(&done)),
    }
}

// --- pull -----------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct PullOptions {
    pub vm: Option<String>,
    pub policy: Policy,
}

enum PullStep {
    Done(Transfer),
    /// Start over from byte 0 without an etag (the file changed, or our part was bad).
    Restart(TransferError),
    Dropped(String),
    Fail(TransferError),
}

fn part_path(dest: &Path, id: &str) -> PathBuf {
    let name = dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    let short: String = id.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    dest.with_file_name(format!(".{name}.azula-{short}.part"))
}

/// Copy `remote` (a file in the VM) to `local` (or stdout, for `-`).
pub async fn pull(
    dialer: &Dialer,
    store: &TransferStore,
    remote: &str,
    local: &str,
    opts: &PullOptions,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Transfer, TransferError> {
    if local == "-" {
        return pull_stdout(dialer, remote, opts).await;
    }
    let name = basename(remote).ok_or_else(|| TransferError::file("not_a_file", "the remote path does not name a file"))?;
    let mut dest = PathBuf::from(local);
    if local.ends_with('/') || dest.is_dir() {
        dest.push(name);
    }
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await.map_err(|e| TransferError::file("io_error", format!("{}: {e}", parent.display())))?;
    }
    let abs_dest = std::fs::canonicalize(dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))).map(|p| p.join(dest.file_name().unwrap_or_default())).unwrap_or_else(|_| dest.clone());

    let mut session = dialer.session().await?;
    let vm = session.resolve_vm(opts.vm.as_deref());
    let key = format!("pull|{}|{vm}|{}|{remote}", session.host(), abs_dest.display());
    let mut outage = Outage::new();
    let mut restarts = 0u32;
    let mut first_offset: Option<u64> = None;
    let pos = std::cell::Cell::new(0u64);
    let mut tracked = |d: u64, t: u64| {
        pos.set(d);
        progress(d, t);
    };

    loop {
        // Resume only if we know the file's etag and the part file is there.
        let rec = store.get(&key);
        let (id, etag, offset) = match rec {
            Some(r) if r.etag.is_some() && part_path(&dest, &r.id).is_file() => {
                let len = std::fs::metadata(part_path(&dest, &r.id)).map(|m| m.len()).unwrap_or(0);
                (r.id, r.etag, len)
            }
            Some(r) => {
                let _ = std::fs::remove_file(part_path(&dest, &r.id));
                (uuid::Uuid::new_v4().to_string(), None, 0)
            }
            None => (uuid::Uuid::new_v4().to_string(), None, 0),
        };
        let part = part_path(&dest, &id);
        let step = pull_once(&mut session, &vm, remote, &dest, &part, &id, etag.as_deref(), offset, store, &key, dialer, &mut tracked, &mut first_offset).await;
        session.conn.close(0u32.into(), b"done");
        match step {
            PullStep::Done(mut t) => {
                store.remove(&key);
                t.resumed_from = first_offset.unwrap_or(0);
                return Ok(t);
            }
            PullStep::Restart(e) => {
                let _ = std::fs::remove_file(&part);
                store.remove(&key);
                restarts += 1;
                if restarts > 3 {
                    return Err(e);
                }
                first_offset = Some(0);
            }
            PullStep::Fail(e) => {
                if matches!(&e, TransferError::File { .. }) {
                    let _ = std::fs::remove_file(&part);
                    store.remove(&key);
                }
                return Err(e);
            }
            PullStep::Dropped(why) => {
                outage.notice(&opts.policy, "pull", pos.get());
                outage.wait(&opts.policy, &why).await?;
                loop {
                    match dialer.session().await {
                        Ok(s) => {
                            session = s;
                            break;
                        }
                        Err(Failure::Transport(m)) => outage.wait(&opts.policy, &m).await?,
                        Err(f) => return Err(f.into()),
                    }
                }
                outage.reset();
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn pull_once(
    s: &mut Session,
    vm: &str,
    remote: &str,
    dest: &Path,
    part: &Path,
    id: &str,
    etag: Option<&str>,
    offset: u64,
    store: &TransferStore,
    key: &str,
    dialer: &Dialer,
    progress: &mut dyn FnMut(u64, u64),
    first_offset: &mut Option<u64>,
) -> PullStep {
    let req = Frame::new(json!({"t": "get", "vm": vm, "start": true, "path": remote, "offset": offset, "etag": etag}));
    if let Err(e) = write_frame(&mut s.send, &req).await {
        return PullStep::Dropped(e.to_string());
    }
    let meta = match read_reply(s).await {
        Ok(f) => f,
        Err(e) => return PullStep::Dropped(e),
    };
    match meta.t() {
        "get_meta" => {}
        "error" if meta.str_field("code") == Some("changed") => return PullStep::Restart(TransferError::from_frame(&meta)),
        "error" => return PullStep::Fail(TransferError::from_frame(&meta)),
        other => return PullStep::Fail(TransferError::Broker { code: "internal".into(), msg: format!("unexpected `{other}` frame") }),
    }
    let size = meta.header.get("size").and_then(Value::as_u64).unwrap_or(0);
    let new_etag = meta.str_field("etag").map(str::to_owned);
    let mode = meta.header.get("mode").and_then(Value::as_u64).unwrap_or(0o644) as u32;
    if offset > size {
        return PullStep::Restart(TransferError::file("changed", "the remote file is shorter than the part already downloaded"));
    }
    *first_offset = Some(offset);
    // Persist the etag before any data so an interruption can resume.
    store.put(key, Record { size, mtime_ns: 0, id: id.to_owned(), etag: new_etag });

    let mut hasher = if offset > 0 {
        match hash_file(part, Some(offset)).await {
            Ok(h) => h,
            Err(e) => return PullStep::Fail(TransferError::file("io_error", format!("{}: {e}", part.display()))),
        }
    } else {
        Sha256::new()
    };
    let mut file = match tokio::fs::OpenOptions::new().create(true).append(true).open(part).await {
        Ok(f) => f,
        Err(e) => return PullStep::Fail(TransferError::file("io_error", format!("{}: {e}", part.display()))),
    };
    // Make sure the part is exactly `offset` bytes before appending.
    if file.metadata().await.map(|m| m.len()).unwrap_or(0) != offset {
        let _ = file.set_len(offset).await;
    }
    let mut got = offset;
    loop {
        let f = match read_reply(s).await {
            Ok(f) => f,
            Err(e) => return PullStep::Dropped(e),
        };
        match f.t() {
            "data" => {
                if let Err(e) = file.write_all(&f.payload).await {
                    return PullStep::Fail(TransferError::file("io_error", format!("{}: {e}", part.display())));
                }
                hasher.update(&f.payload);
                got += f.payload.len() as u64;
                progress(got, size);
                if dialer.fault.as_ref().is_some_and(|fl| fl.bytes(f.payload.len() as u64)) {
                    let _ = file.flush().await;
                    s.conn.close(0u32.into(), b"fault injection");
                    return PullStep::Dropped("fault injected".into());
                }
            }
            "get_end" => {
                let _ = file.flush().await;
                drop(file);
                let want_size = f.header.get("size").and_then(Value::as_u64).unwrap_or(size);
                let want_sha = f.str_field("sha256").unwrap_or("").to_owned();
                let digest = hex(hasher.finalize().as_slice());
                if got != want_size || digest != want_sha {
                    return PullStep::Restart(TransferError::file("digest_mismatch", format!("downloaded {got} bytes with sha256 {digest}, the host reports {want_size} bytes with {want_sha}")));
                }
                set_file_mode(part, mode);
                if let Err(e) = std::fs::rename(part, dest) {
                    return PullStep::Fail(TransferError::file("io_error", format!("renaming into {}: {e}", dest.display())));
                }
                return PullStep::Done(Transfer { path: dest.display().to_string(), size: got, sha256: digest, resumed_from: 0 });
            }
            "error" => return PullStep::Fail(TransferError::from_frame(&f)),
            _ => {}
        }
    }
}

/// `pull REMOTE -`: stream to stdout, single attempt (not resumable).
async fn pull_stdout(dialer: &Dialer, remote: &str, opts: &PullOptions) -> Result<Transfer, TransferError> {
    let mut s = dialer.session().await?;
    let vm = s.resolve_vm(opts.vm.as_deref());
    let req = Frame::new(json!({"t": "get", "vm": vm, "start": true, "path": remote, "offset": 0, "etag": null}));
    write_frame(&mut s.send, &req).await.map_err(|e| TransferError::Transport(e.to_string()))?;
    let meta = read_reply(&mut s).await.map_err(TransferError::Transport)?;
    if meta.t() != "get_meta" {
        return Err(TransferError::from_frame(&meta));
    }
    let mut out = tokio::io::stdout();
    let mut hasher = Sha256::new();
    let mut got = 0u64;
    loop {
        let f = read_reply(&mut s).await.map_err(TransferError::Transport)?;
        match f.t() {
            "data" => {
                if let Err(e) = out.write_all(&f.payload).await {
                    super::out::exit_on_broken_pipe(&e);
                    return Err(TransferError::file("io_error", format!("stdout: {e}")));
                }
                hasher.update(&f.payload);
                got += f.payload.len() as u64;
            }
            "get_end" => {
                let _ = out.flush().await;
                let digest = hex(hasher.finalize().as_slice());
                if digest != f.str_field("sha256").unwrap_or("") {
                    return Err(TransferError::file("digest_mismatch", "the streamed bytes do not match the host's digest"));
                }
                s.conn.close(0u32.into(), b"done");
                return Ok(Transfer { path: "-".into(), size: got, sha256: digest, resumed_from: 0 });
            }
            _ => return Err(TransferError::from_frame(&f)),
        }
    }
}

// --- directory trees ------------------------------------------------------------

/// What a `-r` transfer reports.
#[derive(Debug, Clone, PartialEq)]
pub struct TreeResult {
    pub entries: usize,
}

fn outcome_to_error(o: Outcome, what: &str) -> Result<(), TransferError> {
    match o {
        Outcome::Exit { code: Some(0), ref reason, .. } if reason == "exited" => Ok(()),
        Outcome::Exit { code, signal, reason } => Err(TransferError::file("io_error", format!("{what} failed in the VM (exit {code:?}, signal {signal:?}, {reason})"))),
        Outcome::Error { code, msg } => Err(if FILE_CODES.contains(&code.as_str()) { TransferError::File { code, msg } } else { TransferError::Broker { code, msg } }),
        Outcome::Transport(m) => Err(TransferError::Transport(m)),
        Outcome::GaveUp { job } => Err(TransferError::Transport(format!("lost the connection{}", job.map(|j| format!("; {j} may still be running")).unwrap_or_default()))),
        other => Err(TransferError::Transport(format!("unexpected end of transfer: {other:?}"))),
    }
}

/// `push -r LOCAL_DIR REMOTE_DIR`: tar locally, extract with `tar -x -C` in the guest.
pub async fn push_tree(dialer: &Dialer, local: &Path, remote: &str, vm: Option<&str>, policy: Policy) -> Result<TreeResult, TransferError> {
    if !local.is_dir() {
        return Err(TransferError::file("not_found", format!("{} is not a directory", local.display())));
    }
    let tmp = std::env::temp_dir().join(format!("azula-push-{}.tar", uuid::Uuid::new_v4()));
    let (src, out) = (local.to_path_buf(), tmp.clone());
    tokio::task::spawn_blocking(move || super::tarx::build_tar(&src, &out))
        .await
        .map_err(|e| TransferError::file("io_error", e.to_string()))?
        .map_err(|e| TransferError::file("io_error", format!("{e:#}")))?;
    let entries = tokio::task::spawn_blocking({
        let t = tmp.clone();
        move || tar::Archive::new(std::fs::File::open(&t)?).entries().map(|e| e.count())
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(0);
    let file = tokio::fs::File::open(&tmp).await.map_err(|e| TransferError::file("io_error", e.to_string()))?;
    let req = ExecRequest {
        vm: vm.map(str::to_owned),
        argv: vec!["sh".into(), "-c".into(), "mkdir -p \"$1\" && tar -x -C \"$1\"".into(), "azula-push".into(), remote.to_owned()],
        stdin: true,
        timeout_s: Some(3600),
        label: Some("push -r".into()),
        ..Default::default()
    };
    let (_itx, irx) = mpsc::channel(1);
    let mut stderr_note = |ev: &Event| {
        if let Event::Stderr { data, .. } = ev {
            eprint!("{}", String::from_utf8_lossy(data));
        }
    };
    let (outcome, _) = run_job(dialer, Start::Exec(req), Some(Box::new(file)), irx, policy, &mut stderr_note).await;
    let _ = std::fs::remove_file(&tmp);
    outcome_to_error(outcome, "tar -x")?;
    Ok(TreeResult { entries })
}

/// `pull -r REMOTE_DIR LOCAL_DIR`: `tar -c` in the guest, extracted defensively here.
pub async fn pull_tree(dialer: &Dialer, remote: &str, local: &Path, vm: Option<&str>, policy: Policy) -> Result<TreeResult, TransferError> {
    let tmp = std::env::temp_dir().join(format!("azula-pull-{}.tar", uuid::Uuid::new_v4()));
    let mut file = std::fs::File::create(&tmp).map_err(|e| TransferError::file("io_error", e.to_string()))?;
    let req = ExecRequest {
        vm: vm.map(str::to_owned),
        argv: vec!["tar".into(), "-c".into(), "-C".into(), remote.to_owned(), ".".into()],
        timeout_s: Some(3600),
        label: Some("pull -r".into()),
        ..Default::default()
    };
    let (_itx, irx) = mpsc::channel(1);
    let mut write_err: Option<std::io::Error> = None;
    let mut sink = |ev: &Event| {
        use std::io::Write;
        match ev {
            Event::Stdout { data, .. } => {
                if let Err(e) = file.write_all(data) {
                    write_err.get_or_insert(e);
                }
            }
            Event::Stderr { data, .. } => eprint!("{}", String::from_utf8_lossy(data)),
            _ => {}
        }
    };
    let (outcome, _) = run_job(dialer, Start::Exec(req), None, irx, policy, &mut sink).await;
    drop(file);
    if let Some(e) = write_err {
        let _ = std::fs::remove_file(&tmp);
        return Err(TransferError::file("io_error", format!("writing the archive: {e}")));
    }
    let res = outcome_to_error(outcome, "tar -c");
    let result = match res {
        Ok(()) => {
            let (t, d) = (tmp.clone(), local.to_path_buf());
            tokio::task::spawn_blocking(move || super::tarx::extract_safe(std::fs::File::open(&t)?, &d))
                .await
                .map_err(|e| TransferError::file("io_error", e.to_string()))
                .and_then(|r| r.map_err(|e| TransferError::file("io_error", format!("unsafe or invalid archive: {e:#}"))))
                .map(|entries| TreeResult { entries })
        }
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_file(&tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_notice_names_the_position() {
        assert_eq!(resume_notice("push", 3_040_870), "azula: connection lost, resuming push at 2.9 MiB");
        assert_eq!(resume_notice("pull", 0), "azula: connection lost, resuming pull at 0 B");
    }

    #[test]
    fn basenames() {
        assert_eq!(basename("/a/b/c.txt"), Some("c.txt"));
        assert_eq!(basename("c.txt"), Some("c.txt"));
        assert_eq!(basename("dir/"), Some("dir"));
        assert_eq!(basename("/"), None);
        assert_eq!(basename(".."), None);
    }

    #[test]
    fn part_files_sit_next_to_the_destination() {
        let p = part_path(Path::new("/x/out/app.tgz"), "1234abcd-ffff");
        assert_eq!(p, PathBuf::from("/x/out/.app.tgz.azula-1234abcd.part"));
    }

    #[test]
    fn error_classification_and_exit_codes() {
        let f = |code: &str| Frame::new(json!({"t": "error", "code": code, "msg": "m"}));
        for c in ["not_found", "not_a_file", "exists", "is_a_directory", "not_a_directory", "changed", "size_mismatch", "digest_mismatch", "io_error"] {
            assert_eq!(TransferError::from_frame(&f(c)).exit_code(), 1, "{c}");
        }
        for c in ["unauthorized", "forbidden", "vm_not_running", "busy", "host_busy"] {
            assert_eq!(TransferError::from_frame(&f(c)).exit_code(), 125, "{c}");
        }
        assert_eq!(TransferError::Transport("x".into()).exit_code(), 255);
    }

    #[test]
    fn store_round_trips_and_forgets() {
        let p = std::env::temp_dir().join(format!("azula-xfer-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let s = TransferStore::new(&p);
        assert!(s.is_empty());
        s.put("k", Record { size: 3, mtime_ns: 9, id: "u".into(), etag: Some("e".into()) });
        assert_eq!(TransferStore::new(&p).get("k").unwrap().id, "u");
        s.remove("k");
        assert!(s.is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
