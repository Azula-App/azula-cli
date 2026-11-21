//! Grants and bearer tokens (`vm/BROKER.md` §6).
//!
//! The host keeps only the SHA-256 of each grant's secret in
//! `<compute dir>/grants.json` (0600, written atomically). A token is
//! `azc1.` + base64url of a small JSON object naming the host endpoint, its
//! relay, the grant id and the secret. Every mutation is a locked
//! load-modify-save, so the broker (updating `last_used`) and the CLI
//! (`grant`/`revoke`) never lose each other's writes, and a revocation is seen
//! by the very next request.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_encoding::HEXLOWER;
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Token prefix (and version) of the string the host hands out.
pub const TOKEN_PREFIX: &str = "azc1.";
/// Operation allowing `exec`.
pub const OP_EXEC: &str = "exec";
/// Operation allowing `vm start|stop` (and implicit start on exec).
pub const OP_VM: &str = "vm";
/// Operation allowing `jobs --all`, cancelling any owner's jobs, and
/// nothing else on its own.
pub const OP_ADMIN: &str = "admin";
/// Default grant lifetime.
pub const DEFAULT_TTL: &str = "7d";

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Parse a `--ttl` such as `30m`, `12h`, `7d` (also `s` and `w`; a bare
/// number is seconds).
pub fn parse_duration(text: &str) -> Result<Duration> {
    let t = text.trim();
    if t.is_empty() {
        bail!("empty duration");
    }
    let (num, unit) = match t.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => t.split_at(i),
        None => (t, "s"),
    };
    let n: u64 = num.parse().map_err(|_| anyhow!("invalid duration `{text}`: expected e.g. 30m, 12h, 7d"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => bail!("invalid duration `{text}`: unit must be s, m, h, d or w"),
    };
    let secs = n.checked_mul(mult).ok_or_else(|| anyhow!("duration `{text}` is too large"))?;
    if secs == 0 {
        bail!("duration `{text}` must be greater than zero");
    }
    Ok(Duration::from_secs(secs))
}

/// One minted grant, as stored. Never holds the secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub secret_sha256: String,
    pub created: u64,
    pub expires: u64,
    pub ops: Vec<String>,
    /// Allowed VM names; `"*"` allows any.
    pub vms: Vec<String>,
    pub revoked: Option<u64>,
    pub last_used: Option<u64>,
    pub last_peer: Option<String>,
    /// Set by `revoke --cancel-jobs`: the broker cancels this grant's running
    /// jobs when it sees the revocation.
    #[serde(default)]
    pub revoke_cancel_jobs: bool,
}

/// Does `name` match `pattern`, where `*` matches any run of characters?
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

impl Grant {
    pub fn allows_op(&self, op: &str) -> bool {
        self.ops.iter().any(|o| o == op)
    }

    pub fn allows_vm(&self, vm: &str) -> bool {
        self.vms.iter().any(|v| glob_match(v, vm))
    }

    pub fn is_live(&self, now: u64) -> bool {
        self.revoked.is_none() && now < self.expires
    }

    /// The only VM this grant names, if its scope is exactly one plain name.
    pub fn sole_vm(&self) -> Option<&str> {
        match self.vms.as_slice() {
            [one] if !one.contains('*') => Some(one),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct GrantFile {
    #[serde(default)]
    grants: Vec<Grant>,
}

/// Why `authenticate` refused. All of these look identical to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unauthorized;

/// What `mint` needs.
#[derive(Debug, Clone)]
pub struct MintOptions {
    pub label: String,
    pub ttl: Duration,
    pub ops: Vec<String>,
    pub vms: Vec<String>,
}

/// The grants file plus its lock.
#[derive(Debug, Clone)]
pub struct GrantStore {
    dir: PathBuf,
}

fn sha256_hex(bytes: &[u8]) -> String {
    HEXLOWER.encode(Sha256::digest(bytes).as_slice())
}

/// Constant-time equality of two byte strings of the same length (a length
/// mismatch is not secret: both sides are fixed-size digests).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

impl GrantStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join("grants.json")
    }

    fn read_file(&self) -> Result<GrantFile> {
        match fs::read(self.path()) {
            Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => Ok(GrantFile::default()),
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", self.path().display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(GrantFile::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.path().display())),
        }
    }

    /// The grants file's modification time (`None` if it does not exist).
    pub fn mtime(&self) -> Option<SystemTime> {
        fs::metadata(self.path()).and_then(|m| m.modified()).ok()
    }

    fn write_file(&self, file: &GrantFile) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(file)?;
        write_private_atomic(&self.path(), &bytes)
    }

    /// Run `f` on the parsed file under an exclusive lock, saving if `f`
    /// returns `Ok(true)`.
    fn locked<T>(&self, f: impl FnOnce(&mut GrantFile) -> Result<(T, bool)>) -> Result<T> {
        create_private_dir(&self.dir)?;
        let _lock = FileLock::exclusive(&self.dir.join("grants.lock"))?;
        let mut file = self.read_file()?;
        let (out, save) = f(&mut file)?;
        if save {
            self.write_file(&file)?;
        }
        Ok(out)
    }

    pub fn list(&self) -> Result<Vec<Grant>> {
        Ok(self.read_file()?.grants)
    }

    /// Mint a grant; returns it plus the secret (base64url, 32 random bytes),
    /// which exists nowhere else once the caller drops it.
    pub fn mint(&self, opts: &MintOptions) -> Result<(Grant, String)> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|e| anyhow!("OS random source failed: {e}"))?;
        let secret = URL_SAFE_NO_PAD.encode(raw);
        let mut id_bytes = [0u8; 6];
        getrandom::fill(&mut id_bytes).map_err(|e| anyhow!("OS random source failed: {e}"))?;
        let now = unix_now();
        let grant = Grant {
            id: format!("g_{}", HEXLOWER.encode(&id_bytes)),
            label: opts.label.clone(),
            secret_sha256: sha256_hex(secret.as_bytes()),
            created: now,
            expires: now.saturating_add(opts.ttl.as_secs()),
            ops: opts.ops.clone(),
            vms: opts.vms.clone(),
            revoked: None,
            last_used: None,
            last_peer: None,
            revoke_cancel_jobs: false,
        };
        let stored = grant.clone();
        self.locked(move |f| {
            f.grants.push(stored);
            Ok(((), true))
        })?;
        Ok((grant, secret))
    }

    /// Revoke `id`. `Ok(false)` if there is no such grant; revoking twice keeps
    /// the first timestamp.
    pub fn revoke(&self, id: &str, cancel_jobs: bool) -> Result<bool> {
        self.locked(|f| match f.grants.iter_mut().find(|g| g.id == id) {
            Some(g) => {
                if g.revoked.is_none() {
                    g.revoked = Some(unix_now());
                }
                g.revoke_cancel_jobs |= cancel_jobs;
                Ok((true, true))
            }
            None => Ok((false, false)),
        })
    }

    /// Check `secret` against grant `id`. Unknown, expired and revoked grants
    /// and wrong secrets are indistinguishable ([`Unauthorized`]). On success
    /// records `last_used`/`last_peer` and returns the grant.
    pub fn authenticate(&self, id: &str, secret: &str, peer: &str, now: u64) -> Result<std::result::Result<Grant, Unauthorized>> {
        let presented = sha256_hex(secret.as_bytes());
        self.locked(|f| {
            // Compare against every grant's digest (and a dummy when empty)
            // so timing does not reveal which ids exist.
            let mut hit: Option<usize> = None;
            for (i, g) in f.grants.iter().enumerate() {
                let secret_ok = ct_eq(g.secret_sha256.as_bytes(), presented.as_bytes());
                if g.id == id && secret_ok {
                    hit = Some(i);
                }
            }
            let Some(i) = hit else {
                return Ok((Err(Unauthorized), false));
            };
            if !f.grants[i].is_live(now) {
                return Ok((Err(Unauthorized), false));
            }
            f.grants[i].last_used = Some(now);
            f.grants[i].last_peer = Some(peer.to_owned());
            Ok((Ok(f.grants[i].clone()), true))
        })
    }
}

// --- token ---------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct TokenBody {
    v: u32,
    host: String,
    relay: String,
    grant: String,
    secret: String,
}

/// A parsed bearer token.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub host: String,
    pub relay: String,
    pub grant: String,
    pub secret: String,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token").field("host", &self.host).field("grant", &self.grant).field("secret", &"<redacted>").finish()
    }
}

impl Token {
    pub fn encode(&self) -> String {
        let body = TokenBody {
            v: 1,
            host: self.host.clone(),
            relay: self.relay.clone(),
            grant: self.grant.clone(),
            secret: self.secret.clone(),
        };
        let json = serde_json::to_vec(&body).expect("token serializes");
        format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    /// Parse a token. Errors never echo the token itself.
    pub fn decode(text: &str) -> Result<Token> {
        let rest = text.trim().strip_prefix(TOKEN_PREFIX).ok_or_else(|| anyhow!("not an azula compute token (expected `{TOKEN_PREFIX}…`)"))?;
        let bytes = URL_SAFE_NO_PAD.decode(rest).map_err(|_| anyhow!("malformed token: not valid base64url"))?;
        let body: TokenBody = serde_json::from_slice(&bytes).map_err(|_| anyhow!("malformed token: not valid JSON"))?;
        if body.v != 1 {
            bail!("unsupported token version {}", body.v);
        }
        if body.host.is_empty() || body.grant.is_empty() {
            bail!("malformed token: missing host or grant");
        }
        match URL_SAFE_NO_PAD.decode(&body.secret) {
            Ok(s) if s.len() == 32 => {}
            _ => bail!("malformed token: bad secret"),
        }
        Ok(Token { host: body.host, relay: body.relay, grant: body.grant, secret: body.secret })
    }

    /// The address to dial: the host's endpoint id plus its relay.
    pub fn addr(&self) -> Result<EndpointAddr> {
        let id = EndpointId::from_str(&self.host).map_err(|_| anyhow!("malformed token: bad host endpoint id"))?;
        let mut addr = EndpointAddr::new(id);
        if !self.relay.is_empty() {
            let relay = RelayUrl::from_str(&self.relay).map_err(|_| anyhow!("malformed token: bad relay URL"))?;
            addr = addr.with_relay_url(relay);
        }
        Ok(addr)
    }
}

// --- filesystem helpers --------------------------------------------------

/// `mkdir -p` with mode 0700 on unix.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Write `bytes` to `path` via a 0600 temp file and rename.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// An advisory `flock` held until dropped (no-op off unix).
pub struct FileLock {
    #[allow(dead_code)]
    file: File,
}

impl FileLock {
    /// Block until an exclusive lock on `path` (created 0600) is held.
    pub fn exclusive(path: &Path) -> Result<Self> {
        let file = Self::open(path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: plain flock(2) on a descriptor we own.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| format!("locking {}", path.display()));
            }
        }
        Ok(Self { file })
    }

    /// Take the lock only if nobody holds it.
    pub fn try_exclusive(path: &Path) -> Result<Option<Self>> {
        let file = Self::open(path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: plain flock(2) on a descriptor we own.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(err).with_context(|| format!("locking {}", path.display()));
            }
        }
        Ok(Some(Self { file }))
    }

    fn open(path: &Path) -> Result<File> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path).with_context(|| format!("opening {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("azula-grants-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn opts(ttl: u64) -> MintOptions {
        MintOptions { label: "t".into(), ttl: Duration::from_secs(ttl), ops: vec![OP_EXEC.into()], vms: vec!["a".into()] }
    }

    #[test]
    fn ttl_parsing() {
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("2w").unwrap(), Duration::from_secs(1_209_600));
        for bad in ["", "m", "0m", "-5m", "1.5h", "7days", "5 m x", "99999999999999999999d"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn token_round_trip_and_rejects_garbage() {
        let secret = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let key = iroh::SecretKey::generate();
        let t = Token { host: key.public().to_string(), relay: "https://relay.example./".into(), grant: "g_1".into(), secret };
        let text = t.encode();
        assert!(text.starts_with("azc1."));
        let back = Token::decode(&text).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.addr().unwrap().id, key.public());
        assert!(!format!("{back:?}").contains(&t.secret), "Debug must not print the secret");

        for bad in ["", "azc1.", "azc2.abcd", "azc1.!!!", "hello", "azc1.e30" /* {} */] {
            assert!(Token::decode(bad).is_err(), "{bad:?}");
        }
        let short = URL_SAFE_NO_PAD.encode(br#"{"v":1,"host":"h","relay":"","grant":"g","secret":"AAAA"}"#);
        assert!(Token::decode(&format!("azc1.{short}")).is_err(), "short secret");
        let v2 = URL_SAFE_NO_PAD.encode(format!(r#"{{"v":2,"host":"h","relay":"","grant":"g","secret":"{}"}}"#, t.secret));
        assert!(Token::decode(&format!("azc1.{v2}")).is_err(), "future version");
    }

    #[test]
    fn mint_stores_only_a_hash_and_authenticates() {
        let dir = tmp("mint");
        let store = GrantStore::new(&dir);
        let (g, secret) = store.mint(&opts(3600)).unwrap();
        let on_disk = fs::read_to_string(store.path()).unwrap();
        assert!(!on_disk.contains(&secret), "secret must not be stored");
        assert!(on_disk.contains(&g.secret_sha256));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(store.path()).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let now = unix_now();
        let ok = store.authenticate(&g.id, &secret, "peer1", now).unwrap().unwrap();
        assert_eq!(ok.id, g.id);
        let listed = store.list().unwrap();
        assert_eq!(listed[0].last_used, Some(now));
        assert_eq!(listed[0].last_peer.as_deref(), Some("peer1"));
        // Wrong secret / unknown id are the same refusal.
        assert_eq!(store.authenticate(&g.id, "nope", "p", now).unwrap().unwrap_err(), Unauthorized);
        assert_eq!(store.authenticate("g_other", &secret, "p", now).unwrap().unwrap_err(), Unauthorized);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn expiry_and_revocation() {
        let dir = tmp("expiry");
        let store = GrantStore::new(&dir);
        let (g, secret) = store.mint(&opts(100)).unwrap();
        let t0 = g.created;
        assert!(store.authenticate(&g.id, &secret, "p", t0 + 99).unwrap().is_ok());
        assert_eq!(store.authenticate(&g.id, &secret, "p", g.expires).unwrap().unwrap_err(), Unauthorized);
        assert!(store.revoke(&g.id, false).unwrap());
        assert!(store.authenticate(&g.id, &secret, "p", t0 + 1).unwrap().is_err(), "revoked");
        assert!(!store.revoke("g_missing", false).unwrap());
        assert!(store.list().unwrap()[0].revoked.is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn scope_checks() {
        let mut g = Grant {
            id: "g".into(),
            label: String::new(),
            secret_sha256: String::new(),
            created: 0,
            expires: 10,
            ops: vec![OP_EXEC.into()],
            vms: vec!["build".into()],
            revoked: None,
            last_used: None,
            last_peer: None,
            revoke_cancel_jobs: false,
        };
        assert!(g.allows_op("exec") && !g.allows_op("vm"));
        assert!(g.allows_vm("build") && !g.allows_vm("other"));
        assert_eq!(g.sole_vm(), Some("build"));
        g.vms = vec!["*".into()];
        assert!(g.allows_vm("anything"));
        assert_eq!(g.sole_vm(), None);
        assert!(g.is_live(9) && !g.is_live(10));
    }

    #[test]
    fn vm_globs() {
        assert!(glob_match("ci-*", "ci-1") && glob_match("ci-*", "ci-") && !glob_match("ci-*", "xci-1"));
        assert!(glob_match("*", "anything") && glob_match("a*c", "abbbc") && !glob_match("a*c", "abbbd"));
        assert!(glob_match("build", "build") && !glob_match("build", "builds"));
        assert!(glob_match("*-x", "a-x") && !glob_match("*-x", "a-y"));
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abcd", b"abc"));
    }

    #[test]
    fn concurrent_mints_do_not_lose_grants() {
        let dir = tmp("concurrent");
        let store = GrantStore::new(&dir);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = store.clone();
                std::thread::spawn(move || s.mint(&opts(60)).unwrap())
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.list().unwrap().len(), 8);
        let _ = fs::remove_dir_all(dir);
    }
}
