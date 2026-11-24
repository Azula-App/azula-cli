//! Put and get by a root worker with `--run-as azula`: the files are the job
//! user's business, the worker's records stay root's. These need root and a
//! user `azula` (a disposable VM), and pass without testing anything elsewhere:
//!
//!   cargo test --target aarch64-unknown-linux-musl --test run_as --no-run
#![cfg(target_os = "linux")]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::net::TcpStream;
use std::os::unix::fs::{chown, symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use azula_guest::files::prune_stale_parts;
use azula_guest::frame::Frame;
use azula_guest::fscreds::AsUser;
use azula_guest::identity::{resolve, Identity};
use azula_guest::sha256::Sha256;
use common::*;
use serde_json::{json, Value};

/// The job user, or None where this can't be tested.
fn job_user() -> Option<Identity> {
    let id = resolve("azula");
    if id.switch && id.uid != 0 {
        return Some(id);
    }
    eprintln!("skipped: needs root and a user azula");
    None
}

macro_rules! job_user_or_skip {
    () => {
        match job_user() {
            Some(id) => id,
            None => return,
        }
    };
}

/// A directory of the job user's, in its home.
struct UserDir(PathBuf);

impl UserDir {
    fn new(id: &Identity) -> UserDir {
        let p = Path::new(&id.home).join(format!("run-as-{}", uniq()));
        fs::create_dir(&p).unwrap();
        give(&p, id, 0o755);
        UserDir(p)
    }
    fn join(&self, p: &str) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for UserDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn give(p: &Path, id: &Identity, mode: u32) {
    chown(p, Some(id.uid), Some(id.gid)).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

fn root_dir(env: &Env, name: &str, mode: u32) -> PathBuf {
    let p = env.files().join(name);
    fs::create_dir_all(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p
}

/// uid, gid and permission bits.
fn owner(p: &Path) -> (u32, u32, u32) {
    let m = fs::symlink_metadata(p).unwrap();
    (m.uid(), m.gid(), m.mode() & 0o7777)
}

fn sha(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.hex()
}

fn open_put(env: &Env, path: &str, upload: &str, extra: Value) -> (Client<TcpStream>, Frame) {
    let mut c = env.client();
    c.send(
        merge(
            json!({"t":"put","owner":"g_a","path":path,"upload":upload}),
            extra,
        ),
        &[],
    );
    let f = c.recv();
    (c, f)
}

fn eof(c: &mut Client<TcpStream>, data: &[u8]) -> Frame {
    c.send(json!({"t":"eof","size":data.len(),"sha256":sha(data)}), &[]);
    c.recv()
}

/// A whole put: the last frame.
fn put(env: &Env, path: &Path, data: &[u8], extra: Value) -> Frame {
    let (mut c, f) = open_put(env, &path_str(path), &uniq(), extra);
    if f.t != "put_ready" {
        return f;
    }
    c.send(json!({"t":"data"}), data);
    eof(&mut c, data)
}

/// A whole get: the bytes, or the error frame.
fn get(env: &Env, path: &Path) -> Result<Vec<u8>, Frame> {
    let mut c = env.client();
    c.send(json!({"t":"get","owner":"g_a","path":path_str(path)}), &[]);
    let mut data = vec![];
    loop {
        let f = c.recv();
        match f.t.as_str() {
            "get_meta" => {}
            "data" => data.extend_from_slice(&f.payload),
            "get_end" => {
                assert_eq!(f.header["sha256"], sha(&data));
                return Ok(data);
            }
            _ => return Err(f),
        }
    }
}

fn denied(f: &Frame) -> bool {
    let msg = f.header["msg"].as_str().unwrap_or_default();
    f.t == "error"
        && f.header["code"] == "io_error"
        && (msg.contains("Permission denied") || msg.contains("Operation not permitted"))
}

fn records(env: &Env) -> Vec<PathBuf> {
    fs::read_dir(env.state_dir().join("uploads"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect()
}

/// What a `/proc/*/status` says about access to files.
#[derive(Debug, PartialEq)]
struct Status {
    fs_uid: u32,
    fs_gid: u32,
    groups: BTreeSet<u32>,
    cap_eff: String,
}

fn parse_status(s: &str) -> Status {
    let field = |name: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("no {name} in {s}"))
            .trim()
    };
    let fs_id = |name| {
        let ids: Vec<_> = field(name).split_whitespace().collect();
        ids[3].parse().unwrap()
    };
    Status {
        fs_uid: fs_id("Uid:"),
        fs_gid: fs_id("Gid:"),
        groups: field("Groups:")
            .split_whitespace()
            .map(|g| g.parse().unwrap())
            .collect(),
        cap_eff: field("CapEff:").into(),
    }
}

fn this_thread() -> Status {
    parse_status(&fs::read_to_string("/proc/thread-self/status").unwrap())
}

#[test]
fn the_guard_gives_this_thread_a_jobs_credentials_and_takes_them_back() {
    let id = job_user_or_skip!();
    let env = start();
    let job = run(&env, exec_req("g_a", &["cat", "/proc/self/status"]));
    let job = parse_status(&String::from_utf8(job.stdout).unwrap());
    let before = this_thread();
    assert_eq!((before.fs_uid, before.fs_gid), (0, 0));
    assert_eq!((job.fs_uid, job.fs_gid), (id.uid, id.gid));
    assert_ne!(before.groups, job.groups);

    let (ask, asked) = mpsc::channel::<()>();
    let (tell, told) = mpsc::channel();
    let other = thread::spawn(move || {
        while asked.recv().is_ok() {
            tell.send(this_thread()).unwrap();
        }
    });

    let guard = AsUser::enter(&id).unwrap();
    assert_eq!(this_thread(), job);
    ask.send(()).unwrap();
    assert_eq!(told.recv().unwrap(), before, "another thread changed");
    // Nested, as an early return or a helper might.
    drop(AsUser::enter(&id).unwrap());
    assert_eq!(this_thread(), job);
    drop(guard);
    assert_eq!(this_thread(), before);

    let panicked = std::panic::catch_unwind(|| {
        let _guard = AsUser::enter(&resolve("azula")).unwrap();
        assert_eq!(this_thread().fs_uid, 0, "this panics");
    });
    assert!(panicked.is_err());
    assert_eq!(this_thread(), before);
    drop(ask);
    other.join().unwrap();
}

#[test]
fn a_refused_switch_is_an_error_and_changes_nothing() {
    let mut id = job_user_or_skip!();
    let before = this_thread();
    id.uid = u32::MAX; // no uid: the kernel ignores it, silently
    let e = AsUser::enter(&id).err().expect("must not succeed");
    assert!(
        e.to_string().contains("the kernel refused the credentials"),
        "{e}"
    );
    assert_eq!(this_thread(), before);
}

#[test]
fn put_is_refused_where_a_job_is() {
    let id = job_user_or_skip!();
    let env = start();
    let private = root_dir(&env, "private", 0o700);
    let public = root_dir(&env, "public", 0o755);
    let sticky = root_dir(&env, "sticky", 0o1777);
    for d in [&private, &public, &sticky] {
        fs::write(d.join("existing"), b"root's").unwrap();
    }
    let dir = UserDir::new(&id);
    symlink(&private, dir.join("link")).unwrap();
    for target in [
        private.join("new"),
        private.join("existing"),
        private.join("sub/new"),
        public.join("new"),
        public.join("existing"),
        public.join("sub/new"),
        sticky.join("existing"),
        dir.join("link/new"),
        env.state_dir().join("uploads/u.json"),
        env.state_dir().join("jobs/j/job.json"),
        PathBuf::from("/root/new"),
        PathBuf::from("/etc/azula-run-as-test"),
        // Another user's process: only CAP_SYS_PTRACE opens it.
        PathBuf::from("/proc/1/root/tmp").join(uniq()),
    ] {
        let f = put(&env, &target, b"mine", json!({}));
        assert!(denied(&f), "{}: {f:?}", target.display());
    }
    for d in [&private, &public, &sticky] {
        assert_eq!(fs::read(d.join("existing")).unwrap(), b"root's");
        let mut names: Vec<_> = fs::read_dir(d).unwrap().flatten().collect();
        // The sticky directory's part file is the job user's, and stays for a
        // retry, as after any other failed rename.
        names.retain(|e| !(d == &sticky && e.file_name() != "existing"));
        assert_eq!(names.len(), 1, "{names:?}");
    }
    assert!(!Path::new("/etc/azula-run-as-test").exists());
    assert!(!Path::new("/root/new").exists());
}

#[test]
fn put_makes_files_and_directories_as_the_job_user() {
    let id = job_user_or_skip!();
    let env = start();
    let dir = UserDir::new(&id);
    let target = dir.join("a/b/c.bin");
    let (mut c, f) = open_put(&env, &path_str(&target), "u-own", json!({"mode":0o750}));
    assert_eq!(f.t, "put_ready", "{f:?}");
    c.send(json!({"t":"data"}), b"hello");
    let part = dir.join("a/b/.c.bin.azula-u-own.part");
    wait_for("the part file", 5, || {
        fs::metadata(&part).is_ok_and(|m| m.len() == 5)
    });
    assert_eq!(owner(&part), (id.uid, id.gid, 0o600));
    // The record is root's, while the transfer runs.
    let recs = records(&env);
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(owner(&recs[0]).0, 0);
    let f = eof(&mut c, b"hello");
    assert_eq!(f.t, "put_ok", "{f:?}");
    assert_eq!(owner(&target), (id.uid, id.gid, 0o750));
    assert_eq!(owner(&dir.join("a")), (id.uid, id.gid, 0o755));
    assert_eq!(owner(&dir.join("a/b")), (id.uid, id.gid, 0o755));
    assert!(!part.exists());
    assert!(records(&env).is_empty());

    // Default mode, without clobber, and relative to the home.
    let rel = dir.join("rel/f");
    let rel = rel.strip_prefix(&id.home).unwrap();
    let f = put(&env, rel, b"x", json!({"overwrite":false}));
    assert_eq!(f.t, "put_ok", "{f:?}");
    assert_eq!(owner(&dir.join("rel/f")), (id.uid, id.gid, 0o644));

    // Replacing root's file in the job user's own directory: `mv` can, too.
    fs::write(dir.join("roots"), b"old").unwrap();
    let f = put(&env, &dir.join("roots"), b"new", json!({}));
    assert_eq!(f.t, "put_ok", "{f:?}");
    assert_eq!(owner(&dir.join("roots")), (id.uid, id.gid, 0o644));

    // A setgid directory gives its group away, as it does to a job.
    let shared = dir.join("shared");
    fs::create_dir(&shared).unwrap();
    chown(&shared, Some(id.uid), Some(0)).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o2775)).unwrap();
    let f = put(&env, &shared.join("f"), b"x", json!({}));
    assert_eq!(f.t, "put_ok", "{f:?}");
    assert_eq!(owner(&shared.join("f")), (id.uid, 0, 0o644));
}

#[test]
fn put_resumes() {
    let id = job_user_or_skip!();
    let env = start();
    let dir = UserDir::new(&id);
    // Sticky and world-writable, where fs.protected_regular applies, too.
    for d in [dir.0.clone(), root_dir(&env, "sticky", 0o1777)] {
        let (target, upload) = (d.join("r.bin"), uniq());
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let (mut c, f) = open_put(&env, &path_str(&target), &upload, json!({}));
        assert_eq!(
            (f.t.as_str(), &f.header["offset"]),
            ("put_ready", &json!(0))
        );
        c.send(json!({"t":"data"}), &data[..100_000]);
        drop(c);
        let part = d.join(format!(".r.bin.azula-{upload}.part"));
        wait_for("the first part", 5, || {
            fs::metadata(&part).is_ok_and(|m| m.len() == 100_000)
        });
        assert_eq!(owner(&part), (id.uid, id.gid, 0o600));
        let (mut c, f) = open_put(&env, &path_str(&target), &upload, json!({}));
        assert_eq!(f.header["offset"], 100_000, "{f:?}");
        c.send(json!({"t":"data"}), &data[100_000..]);
        let f = eof(&mut c, &data);
        assert_eq!(f.t, "put_ok", "{f:?}");
        assert_eq!(fs::read(&target).unwrap(), data);
        assert_eq!(owner(&target), (id.uid, id.gid, 0o644));
        assert!(!part.exists());
        assert!(records(&env).is_empty());
    }
}

#[test]
fn a_failed_put_removes_the_users_part_and_roots_record() {
    let id = job_user_or_skip!();
    let env = start();
    fs::set_permissions(env.state_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    let dir = UserDir::new(&id);
    for (size, digest, code) in [
        (4, sha(b"abc"), "size_mismatch"),
        (3, sha(b"xyz"), "digest_mismatch"),
    ] {
        let (mut c, f) = open_put(&env, &path_str(&dir.join("f")), "u-fail", json!({}));
        assert_eq!(f.t, "put_ready", "{f:?}");
        assert_eq!(records(&env).len(), 1);
        c.send(json!({"t":"data"}), b"abc");
        c.send(json!({"t":"eof","size":size,"sha256":digest}), &[]);
        assert_eq!(c.recv().header["code"], code);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
        assert!(records(&env).is_empty());
    }
}

#[test]
fn get_reads_what_a_job_can() {
    let id = job_user_or_skip!();
    let env = start();
    let private = root_dir(&env, "private", 0o700);
    let public = root_dir(&env, "public", 0o755);
    let file = |p: PathBuf, uid: u32, gid: u32, mode: u32| {
        fs::write(&p, b"content").unwrap();
        chown(&p, Some(uid), Some(gid)).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        p
    };
    let dir = UserDir::new(&id);
    let secret = file(public.join("secret"), 0, 0, 0o600);
    symlink(&secret, dir.join("link")).unwrap();
    for target in [
        secret,
        file(private.join("world-readable"), 0, 0, 0o644),
        file(dir.join("roots"), 0, 0, 0o600),
        dir.join("link"),
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/proc/1/root/etc/passwd"),
    ] {
        let f = get(&env, &target).expect_err(&path_str(&target));
        assert!(denied(&f), "{}: {f:?}", target.display());
    }
    let mut readable = vec![
        file(dir.join("own"), id.uid, id.gid, 0o600),
        file(public.join("world"), 0, 0, 0o644),
        file(public.join("group"), 0, id.gid, 0o640),
    ];
    // A supplementary group counts, if the user has one.
    let groups = run(&env, exec_req("g_a", &["id", "-G"])).stdout;
    let groups = String::from_utf8(groups).unwrap();
    let mut groups = groups.split_whitespace().map(|g| g.parse().unwrap());
    match groups.find(|g| *g != id.gid) {
        Some(g) => readable.push(file(public.join("extra"), 0, g, 0o640)),
        None => eprintln!("not tested: azula has no supplementary group"),
    }
    for target in readable {
        let got = get(&env, &target);
        assert_eq!(got.unwrap(), b"content", "{}", target.display());
    }
}

#[test]
fn one_connections_credentials_are_not_anothers() {
    let id = job_user_or_skip!();
    let before = this_thread();
    let env = start();
    // Only root gets at the worker's records now.
    fs::set_permissions(env.state_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    let dir = UserDir::new(&id);
    let private = root_dir(&env, "private", 0o700);
    fs::write(private.join("f"), b"root's").unwrap();
    let own = dir.join("own");
    let big: Vec<u8> = (0..32u32 << 20).map(|i| (i % 253) as u8).collect();
    fs::write(&own, &big).unwrap();
    give(&own, &id, 0o600);

    let half_put = |name: &str| {
        let d = dir.join(name);
        fs::create_dir(&d).unwrap();
        give(&d, &id, 0o755);
        let (mut c, f) = open_put(&env, &path_str(&d.join("f")), &uniq(), json!({}));
        assert_eq!(f.t, "put_ready", "{f:?}");
        c.send(json!({"t":"data"}), b"half");
        (c, d)
    };
    // Two puts and a get are all under way: the get is stuck on a full socket.
    let (mut put_a, _) = half_put("a");
    let (mut put_b, dir_b) = half_put("b");
    let mut getting = env.client();
    getting.send(json!({"t":"get","owner":"g_a","path":path_str(&own)}), &[]);
    assert_eq!(getting.recv().t, "get_meta");
    let users = || {
        let mut n = 0;
        for t in fs::read_dir("/proc/self/task").unwrap().flatten() {
            if let Ok(s) = fs::read_to_string(t.path().join("status")) {
                n += usize::from(parse_status(&s).fs_uid == id.uid);
            }
        }
        n
    };
    wait_for("three threads to be the job user", 5, || users() >= 3);

    // Others do the worker's business as root, and come and go as the user.
    for _ in 0..20 {
        let r = run(&env, exec_req("g_a", &["id", "-u"]));
        assert_eq!(r.stdout, format!("{}\n", id.uid).as_bytes());
        assert_eq!(put(&env, &dir.join("c"), b"c", json!({})).t, "put_ok");
        assert!(denied(&put(&env, &private.join("f"), b"c", json!({}))));
        assert!(denied(&get(&env, &private.join("f")).unwrap_err()));
        assert_eq!(get(&env, &dir.join("c")).unwrap(), b"c");
    }
    assert_eq!(this_thread(), before);

    // Put A is still the user: what it makes is the user's.
    put_a.send(json!({"t":"data"}), b"+half");
    let f = eof(&mut put_a, b"half+half");
    assert_eq!(f.t, "put_ok", "{f:?}");
    assert_eq!(owner(&dir.join("a/f")), (id.uid, id.gid, 0o644));
    // Put B, too: it may not rename in a directory that is root's by now.
    chown(&dir_b, Some(0), Some(0)).unwrap();
    put_b.send(json!({"t":"data"}), b"+half");
    let f = eof(&mut put_b, b"half+half");
    assert!(denied(&f), "{f:?}");
    assert!(!dir_b.join("f").exists());
    // And the get goes on where it was.
    let mut data = vec![];
    loop {
        let f = getting.recv();
        match f.t.as_str() {
            "data" => data.extend_from_slice(&f.payload),
            "get_end" => break assert_eq!(f.header["sha256"], sha(&big)),
            _ => panic!("{f:?}"),
        }
    }
    assert!(data == big);
}

#[test]
fn many_transfers_at_once() {
    let id = job_user_or_skip!();
    let before = this_thread();
    let env = start();
    let dir = UserDir::new(&id);
    let private = root_dir(&env, "private", 0o700);
    fs::write(private.join("f"), b"root's").unwrap();
    thread::scope(|s| {
        for i in 0..8 {
            let (env, dir, private, id) = (&env, &dir, &private, &id);
            s.spawn(move || {
                for n in 0..40 {
                    let p = dir.join(&format!("{i}/{n}/f"));
                    let f = put(env, &p, b"data", json!({"mode":0o640}));
                    assert_eq!(f.t, "put_ok", "{f:?}");
                    assert_eq!(owner(&p), (id.uid, id.gid, 0o640));
                    assert!(denied(&put(env, &private.join("f"), b"x", json!({}))));
                    assert_eq!(get(env, &p).unwrap(), b"data");
                    assert!(denied(&get(env, &private.join("f")).unwrap_err()));
                }
            });
        }
    });
    assert_eq!(fs::read(private.join("f")).unwrap(), b"root's");
    assert_eq!(fs::read_dir(&private).unwrap().count(), 1);
    assert_eq!(this_thread(), before);
}

#[test]
fn stale_parts_are_pruned_as_the_job_user() {
    let id = job_user_or_skip!();
    let env = start();
    let dir = UserDir::new(&id);
    let public = root_dir(&env, "public", 0o755);
    symlink(&public, dir.join("link")).unwrap();
    let stale = |p: PathBuf, uid: u32, upload: &str| {
        let f = fs::File::create(&p).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600))
            .unwrap();
        chown(&p, Some(uid), Some(uid)).unwrap();
        let rec = json!({"owner":"g_a","path":"x","part":path_str(&p)});
        let path = env.state_dir().join(format!("uploads/{upload}.json"));
        fs::write(path, rec.to_string()).unwrap();
        p
    };
    let users = stale(dir.join(".f.azula-u1.part"), id.uid, "u1");
    // The user pointed its directory at root's since.
    stale(dir.join("link/.f.azula-u2.part"), 0, "u2");
    assert_eq!(records(&env).len(), 2);
    prune_stale_parts(&env.srv);
    assert!(!users.exists());
    assert!(public.join(".f.azula-u2.part").exists());
    assert!(records(&env).is_empty());
    assert_eq!(this_thread().fs_uid, 0);
}

/// A root worker must not enter a directory for a job that the job couldn't.
#[test]
fn a_jobs_cwd_is_entered_as_the_job_user() {
    let id = job_user_or_skip!();
    let env = start();
    let locked = root_dir(&env, "locked", 0o700);
    let inner = locked.join("inner");
    fs::create_dir(&inner).unwrap();
    fs::set_permissions(&inner, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(inner.join("secret"), b"root's\n").unwrap();
    let r = run(
        &env,
        merge(
            exec_req("g_a", &["cat", "secret"]),
            json!({"cwd": path_str(&inner)}),
        ),
    );
    assert_eq!((r.last().t.as_str(), r.h("code")), ("error", json!("cwd_missing")), "{:?}", r.last());

    let mine = UserDir::new(&id);
    let r = run(
        &env,
        merge(exec_req("g_a", &["pwd"]), json!({"cwd": path_str(&mine.0)})),
    );
    assert_eq!(String::from_utf8_lossy(&r.stdout), format!("{}\n", path_str(&mine.0)));
}

/// Other owners' records and output, and the worker's salt.
#[test]
fn a_job_cannot_read_the_workers_state() {
    let _id = job_user_or_skip!();
    let env = start();
    let other = detach(&env, exec_req("g_b", &["sh", "-c", "echo private"])).0;
    wait_state(&env, "g_b", &other, "exited");
    let state = path_str(&env.state_dir());
    for path in [format!("{state}/salt"), format!("{state}/jobs"), format!("{state}/jobs/{other}/job.json")] {
        let r = run(&env, exec_req("g_a", &["sh", "-c", &format!("cat {path} || ls {path}")]));
        assert_eq!(r.h("reason"), "exited");
        assert!(r.stdout.is_empty() && r.h("code") != 0, "{path}: {:?}", String::from_utf8_lossy(&r.stdout));
    }
}
