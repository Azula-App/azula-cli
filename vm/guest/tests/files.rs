mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use azula_guest::frame::Frame;
use azula_guest::sha256::Sha256;
use common::*;
use serde_json::{json, Value};

fn sha(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.hex()
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

fn put_header(path: &Path, upload: &str, extra: Value) -> Value {
    merge(
        json!({"t":"put","owner":"g_a","path":path_str(path),"upload":upload}),
        extra,
    )
}

fn open_put(
    env: &Env,
    path: &Path,
    upload: &str,
    extra: Value,
) -> (Client<std::net::TcpStream>, Frame) {
    let mut c = env.client();
    c.send(put_header(path, upload, extra), &[]);
    let f = c.recv();
    (c, f)
}

fn eof(c: &mut Client<std::net::TcpStream>, data: &[u8]) -> Frame {
    c.send(json!({"t":"eof","size":data.len(),"sha256":sha(data)}), &[]);
    c.recv()
}

fn part_files(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".part"))
        .collect()
}

fn put_all(env: &Env, path: &Path, upload: &str, data: &[u8], extra: Value) -> Frame {
    let (mut c, f) = open_put(env, path, upload, extra);
    assert_eq!(f.t, "put_ready", "{f:?}");
    for chunk in data.chunks(1 << 20) {
        c.send(json!({"t":"data"}), chunk);
    }
    let r = eof(&mut c, data);
    c.expect_closed();
    r
}

#[test]
fn put_new_file_atomic_with_digest_and_mode() {
    let env = start();
    let dir = env.files();
    let target = dir.join("sub/deeper/app.bin");
    let data = pattern(3 * (1 << 20) + 17);
    let (mut c, f) = open_put(&env, &target, "u-1", json!({"mode":0o755}));
    assert_eq!(
        (f.t.as_str(), f.header["offset"].clone()),
        ("put_ready", json!(0))
    );
    for chunk in data.chunks(1 << 20) {
        c.send(json!({"t":"data"}), chunk);
    }
    // Not visible until eof.
    assert!(!target.exists());
    assert_eq!(
        part_files(target.parent().unwrap()),
        vec![".app.bin.azula-u-1.part"]
    );
    let r = eof(&mut c, &data);
    assert_eq!(r.t, "put_ok", "{r:?}");
    assert_eq!(r.header["path"], path_str(&target));
    assert_eq!(r.header["size"], data.len());
    assert_eq!(r.header["sha256"], sha(&data));
    c.expect_closed();
    assert_eq!(fs::read(&target).unwrap(), data);
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(part_files(target.parent().unwrap()).is_empty());
}

#[test]
fn put_relative_path_goes_under_home_and_default_mode() {
    let env = start();
    // Home is the (non-root) test user's; use a unique relative dir there.
    let home = std::env::var("HOME").unwrap();
    let rel = format!(".azula-guest-test-{}/f.txt", uniq());
    let r = put_all(&env, Path::new(&rel), "u-rel", b"hello", json!({}));
    assert_eq!(r.t, "put_ok", "{r:?}");
    let abs = Path::new(&home).join(&rel);
    assert_eq!(r.header["path"], path_str(&abs));
    assert_eq!(fs::read(&abs).unwrap(), b"hello");
    assert_eq!(
        fs::metadata(&abs).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let _ = fs::remove_dir_all(abs.parent().unwrap());
}

#[test]
fn put_resume_continues_digest() {
    let env = start();
    let dir = env.files();
    let target = dir.join("resume.bin");
    let data = pattern(2_500_000);
    let split = 1_300_000;
    let (mut c, f) = open_put(&env, &target, "u-res", json!({}));
    assert_eq!(f.header["offset"], 0);
    c.send(json!({"t":"data"}), &data[..1 << 20]);
    c.send(json!({"t":"data"}), &data[1 << 20..split]);
    drop(c);
    let part = dir.join(".resume.bin.azula-u-res.part");
    wait_for("part to reach split", 5, || {
        fs::metadata(&part).map(|m| m.len()).ok() == Some(split as u64)
    });
    assert!(!target.exists());
    assert_eq!(
        fs::metadata(&part).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Resume: worker reports how much it has; client sends the rest.
    let (mut c, f) = open_put(&env, &target, "u-res", json!({}));
    assert_eq!(f.header["offset"], split as u64);
    for chunk in data[split..].chunks(1 << 20) {
        c.send(json!({"t":"data"}), chunk);
    }
    let r = eof(&mut c, &data);
    assert_eq!(r.t, "put_ok", "{r:?}");
    assert_eq!(r.header["sha256"], sha(&data));
    assert_eq!(fs::read(&target).unwrap(), data);
    assert!(!part.exists());
}

#[test]
fn put_digest_mismatch_deletes_part_and_restarts_from_zero() {
    let env = start();
    let dir = env.files();
    let target = dir.join("bad.bin");
    let (mut c, _) = open_put(&env, &target, "u-bad", json!({}));
    c.send(json!({"t":"data"}), b"abcdef");
    c.send(json!({"t":"eof","size":6,"sha256":sha(b"other")}), &[]);
    let r = c.recv();
    assert_eq!(
        (r.t.as_str(), r.header["code"].clone()),
        ("error", json!("digest_mismatch"))
    );
    c.expect_closed();
    assert!(!target.exists());
    assert!(part_files(&dir).is_empty());
    let (c2, f) = open_put(&env, &target, "u-bad", json!({}));
    assert_eq!(f.header["offset"], 0);
    drop(c2);
}

#[test]
fn put_size_mismatch() {
    let env = start();
    let dir = env.files();
    let (mut c, _) = open_put(&env, &dir.join("s.bin"), "u-size", json!({}));
    c.send(json!({"t":"data"}), b"abc");
    c.send(json!({"t":"eof","size":4,"sha256":sha(b"abc")}), &[]);
    let r = c.recv();
    assert_eq!(r.header["code"], "size_mismatch");
    assert!(part_files(&dir).is_empty());
}

#[test]
fn put_no_clobber_and_overwrite() {
    let env = start();
    let dir = env.files();
    let target = dir.join("x.txt");
    fs::write(&target, b"original").unwrap();
    let (_c, f) = open_put(&env, &target, "u-nc", json!({"overwrite":false}));
    assert_eq!(f.header["code"], "exists");
    assert_eq!(fs::read(&target).unwrap(), b"original");
    assert!(part_files(&dir).is_empty());
    let r = put_all(&env, &target, "u-ow", b"replaced", json!({}));
    assert_eq!(r.t, "put_ok");
    assert_eq!(fs::read(&target).unwrap(), b"replaced");
    // Target created between the check and eof is also protected.
    let t2 = dir.join("race.txt");
    let (mut c, f) = open_put(&env, &t2, "u-race", json!({"overwrite":false}));
    assert_eq!(f.t, "put_ready");
    fs::write(&t2, b"someone else").unwrap();
    c.send(json!({"t":"data"}), b"mine");
    let r = eof(&mut c, b"mine");
    assert_eq!(r.header["code"], "exists");
    assert_eq!(fs::read(&t2).unwrap(), b"someone else");
}

#[test]
fn put_path_errors() {
    let env = start();
    let dir = env.files();
    fs::create_dir_all(dir.join("adir")).unwrap();
    fs::write(dir.join("afile"), b"f").unwrap();
    let (_c, f) = open_put(&env, &dir.join("adir"), "u-d", json!({}));
    assert_eq!(f.header["code"], "is_a_directory");
    let (_c, f) = open_put(&env, &dir.join("afile/inner.txt"), "u-nd", json!({}));
    assert_eq!(f.header["code"], "not_a_directory");
    let (_c, f) = open_put(&env, &dir.join("afile/x/inner.txt"), "u-nd2", json!({}));
    assert_eq!(f.header["code"], "not_a_directory");
    let (_c, f) = open_put(
        &env,
        &dir.join("nope/inner.txt"),
        "u-nm",
        json!({"mkdirs":false}),
    );
    assert_eq!(f.header["code"], "io_error");
    assert!(!dir.join("nope").exists());
    let (_c, f) = open_put(&env, &dir.join("x"), "bad id!", json!({}));
    assert_eq!(f.header["code"], "bad_request");
    let mut c = env.client();
    c.send(json!({"t":"put","owner":"g_a","path":"x"}), &[]);
    assert_eq!(c.recv().header["code"], "bad_request");
}

#[test]
fn put_upload_conflict() {
    let env = start();
    let dir = env.files();
    let (c1, f) = open_put(&env, &dir.join("one.bin"), "u-conf", json!({}));
    assert_eq!(f.t, "put_ready");
    drop(c1);
    // Same id, different path.
    let (_c, f) = open_put(&env, &dir.join("two.bin"), "u-conf", json!({}));
    assert_eq!(f.header["code"], "upload_conflict");
    // Same id and path, different owner.
    let mut c = env.client();
    c.send(
        json!({"t":"put","owner":"g_b","path":path_str(&dir.join("one.bin")),"upload":"u-conf"}),
        &[],
    );
    assert_eq!(c.recv().header["code"], "upload_conflict");
    // The rightful owner can still resume.
    let (_c, f) = open_put(&env, &dir.join("one.bin"), "u-conf", json!({}));
    assert_eq!(f.t, "put_ready");
}

#[test]
fn concurrent_puts_to_one_path_each_atomic() {
    let env = start();
    let target = env.files().join("both.bin");
    let (mut a, fa) = open_put(&env, &target, "u-ca", json!({}));
    let (mut b, fb) = open_put(&env, &target, "u-cb", json!({}));
    assert_eq!((fa.t.as_str(), fb.t.as_str()), ("put_ready", "put_ready"));
    a.send(json!({"t":"data"}), b"AAAA");
    b.send(json!({"t":"data"}), b"BBBBBB");
    assert_eq!(eof(&mut a, b"AAAA").t, "put_ok");
    assert_eq!(fs::read(&target).unwrap(), b"AAAA");
    assert_eq!(eof(&mut b, b"BBBBBB").t, "put_ok");
    assert_eq!(fs::read(&target).unwrap(), b"BBBBBB");
}

// ------------------------------------------------------------------ get

fn get_req(path: &Path, extra: Value) -> Value {
    merge(
        json!({"t":"get","owner":"g_a","path":path_str(path)}),
        extra,
    )
}

struct Got {
    meta: Frame,
    data: Vec<u8>,
    end: Frame,
}

fn get_ok(env: &Env, req: Value) -> Got {
    let mut c = env.client();
    c.send(req, &[]);
    let meta = c.recv();
    assert_eq!(meta.t, "get_meta", "{meta:?}");
    let mut data = vec![];
    loop {
        let f = c.recv();
        match f.t.as_str() {
            "data" => {
                assert!(f.payload.len() <= 1 << 20);
                data.extend_from_slice(&f.payload)
            }
            "get_end" => {
                c.expect_closed();
                return Got { meta, data, end: f };
            }
            other => panic!("unexpected {other}: {f:?}"),
        }
    }
}

fn get_err(env: &Env, req: Value) -> String {
    let mut c = env.client();
    c.send(req, &[]);
    let f = c.recv();
    assert_eq!(f.t, "error", "{f:?}");
    f.header["code"].as_str().unwrap().into()
}

#[test]
fn get_whole_file() {
    let env = start();
    let p = env.files().join("g.bin");
    let data = pattern(2_300_000);
    fs::write(&p, &data).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
    let g = get_ok(&env, get_req(&p, json!({"offset":0,"etag":null})));
    assert_eq!(g.data, data);
    assert_eq!(g.meta.header["size"], data.len());
    assert_eq!(g.meta.header["mode"], 0o640);
    assert_eq!(g.meta.header["path"], path_str(&p));
    assert_eq!(g.end.header["size"], data.len());
    assert_eq!(g.end.header["sha256"], sha(&data));
    let etag = g.meta.header["etag"].as_str().unwrap();
    assert_eq!(etag.split(':').count(), 4);
}

#[test]
fn get_resume_with_etag_keeps_whole_file_digest() {
    let env = start();
    let p = env.files().join("r.bin");
    let data = pattern(2_000_000);
    fs::write(&p, &data).unwrap();
    let first = get_ok(&env, get_req(&p, json!({})));
    let etag = first.meta.header["etag"].clone();
    let off = 1_234_567usize;
    let g = get_ok(&env, get_req(&p, json!({"offset":off,"etag":etag})));
    assert_eq!(g.data, &data[off..]);
    assert_eq!(
        g.end.header["sha256"],
        sha(&data),
        "digest covers bytes before offset too"
    );
    // Offset at EOF is valid and empty.
    let g = get_ok(&env, get_req(&p, json!({"offset":data.len()})));
    assert!(g.data.is_empty());
    assert_eq!(g.end.header["sha256"], sha(&data));
    assert_eq!(
        get_err(&env, get_req(&p, json!({"offset":data.len()+1}))),
        "bad_request"
    );
}

#[test]
fn get_changed_etag_is_refused() {
    let env = start();
    let p = env.files().join("c.bin");
    fs::write(&p, b"version one").unwrap();
    let etag = get_ok(&env, get_req(&p, json!({}))).meta.header["etag"].clone();
    fs::write(&p, b"version two, longer").unwrap();
    assert_eq!(
        get_err(&env, get_req(&p, json!({"offset":4,"etag":etag}))),
        "changed"
    );
    // Restart from 0 without an etag works.
    let g = get_ok(&env, get_req(&p, json!({})));
    assert_eq!(g.data, b"version two, longer");
}

#[test]
fn get_follows_symlinks_and_rejects_non_regular() {
    let env = start();
    let dir = env.files();
    let real = dir.join("real.txt");
    fs::write(&real, b"through the link").unwrap();
    std::os::unix::fs::symlink(&real, dir.join("link.txt")).unwrap();
    let g = get_ok(&env, get_req(&dir.join("link.txt"), json!({})));
    assert_eq!(g.data, b"through the link");
    fs::create_dir_all(dir.join("d")).unwrap();
    assert_eq!(
        get_err(&env, get_req(&dir.join("d"), json!({}))),
        "not_a_file"
    );
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(path_str(&fifo)).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert_eq!(get_err(&env, get_req(&fifo, json!({}))), "not_a_file");
    assert_eq!(
        get_err(&env, get_req(&dir.join("missing"), json!({}))),
        "not_found"
    );
    assert_eq!(
        get_err(&env, json!({"t":"get","owner":"g_a"})),
        "bad_request"
    );
}

#[test]
fn put_then_get_round_trip_digest_matches() {
    let env = start();
    let p = env.files().join("rt.bin");
    let data = pattern(1_700_000);
    assert_eq!(put_all(&env, &p, "u-rt", &data, json!({})).t, "put_ok");
    let g = get_ok(&env, get_req(&p, json!({})));
    assert_eq!(g.end.header["sha256"], sha(&data));
}
