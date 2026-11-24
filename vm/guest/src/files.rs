//! Resumable file transfer: put and get (vm/README.md 2.7, 2.8).
//!
//! The target and its part file are touched as the job user (`AsUser`), the
//! upload records as the worker.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::frame::{read_frame, Frame};
use crate::fscreds::AsUser;
use crate::identity::resolve;
use crate::server::{send, send_error, Server};
use crate::sha256::Sha256;
use crate::util::{now_s, valid_id, write_atomic};

const CHUNK: usize = 1 << 20;
const PART_MAX_AGE_S: u64 = 24 * 3600;

#[derive(Serialize, Deserialize)]
struct Upload {
    owner: String,
    path: String,
    part: String,
}

fn resolve_path(home: &str, p: &str) -> Result<PathBuf, String> {
    if p.is_empty() || p.contains('\0') {
        return Err("path must be non-empty and contain no NUL".into());
    }
    Ok(if p.starts_with('/') {
        PathBuf::from(p)
    } else {
        Path::new(home).join(p)
    })
}

/// Remove part files (and their records) untouched for 24 h.
pub fn prune_stale_parts(srv: &Server) {
    let Ok(rd) = fs::read_dir(srv.uploads_dir()) else {
        return;
    };
    let mut uploads: Vec<(PathBuf, Upload)> = rd
        .flatten()
        .filter_map(|e| {
            let up = serde_json::from_slice(&fs::read(e.path()).ok()?).ok()?;
            Some((e.path(), up))
        })
        .collect();
    if uploads.is_empty() {
        return;
    }
    {
        // The path may lead somewhere else by now, so not as root.
        let _user = match AsUser::enter(&resolve(&srv.cfg.run_as)) {
            Ok(u) => u,
            Err(e) => return eprintln!("azula-guest: pruning part files: {e}"),
        };
        uploads.retain(|(_, up)| {
            let stale = match fs::metadata(&up.part) {
                Ok(m) => now_s().saturating_sub(m.mtime().max(0) as u64) > PART_MAX_AGE_S,
                Err(_) => true,
            };
            if stale {
                let _ = fs::remove_file(&up.part);
            }
            stale
        });
    }
    for (rec_path, _) in uploads {
        let _ = fs::remove_file(rec_path);
    }
}

fn io_err<C: Write>(conn: &mut C, e: &io::Error) {
    send_error(conn, "io_error", &e.to_string());
}

/// Ensure the parent directory exists (creating it if `mkdirs`).
fn ensure_parent(parent: &Path, mkdirs: bool) -> Result<(), (&'static str, String)> {
    let mut missing = Vec::new();
    let mut cur = parent;
    loop {
        match fs::metadata(cur) {
            Ok(m) if m.is_dir() => break,
            Ok(_) => {
                return Err((
                    "not_a_directory",
                    format!("{} is not a directory", cur.display()),
                ))
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                return Err((
                    "not_a_directory",
                    format!("a parent of {} is not a directory", cur.display()),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing.push(cur);
                match cur.parent() {
                    Some(p) => cur = p,
                    None => break,
                }
            }
            Err(e) => return Err(("io_error", e.to_string())),
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    if !mkdirs {
        return Err((
            "io_error",
            format!("{}: no such directory (mkdirs is off)", parent.display()),
        ));
    }
    for d in missing.into_iter().rev() {
        fs::create_dir(d).map_err(|e| ("io_error", format!("{}: {e}", d.display())))?;
        let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o755));
    }
    Ok(())
}

fn hash_prefix(f: &mut File, len: u64) -> io::Result<Sha256> {
    let mut h = Sha256::new();
    f.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; CHUNK];
    let mut left = len;
    while left > 0 {
        let n = f.read(&mut buf[..(left.min(CHUNK as u64)) as usize])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        h.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(h)
}

pub fn put<C: Write>(srv: &Arc<Server>, f: &Frame, conn: &mut C, reader: &mut impl Read) {
    let s = |k: &str| f.header.get(k).and_then(Value::as_str);
    let (Some(owner), Some(path), Some(upload)) = (s("owner"), s("path"), s("upload")) else {
        return send_error(conn, "bad_request", "owner, path and upload are required");
    };
    if owner.is_empty() || !valid_id(upload) {
        return send_error(conn, "bad_request", "owner or upload id invalid");
    }
    let mode = f
        .header
        .get("mode")
        .and_then(Value::as_u64)
        .map_or(0o644, |m| (m & 0o777) as u32);
    let overwrite = f
        .header
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mkdirs = f
        .header
        .get("mkdirs")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let id = resolve(&srv.cfg.run_as);
    let target = match resolve_path(&id.home, path) {
        Ok(t) => t,
        Err(m) => return send_error(conn, "bad_request", &m),
    };
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return send_error(conn, "bad_request", "path has no file name");
    };
    let name = name.to_string_lossy().into_owned();
    if name == ".." || name == "." {
        return send_error(conn, "bad_request", "path has no file name");
    }
    {
        let _user = match AsUser::enter(&id) {
            Ok(u) => u,
            Err(e) => return io_err(conn, &e),
        };
        if fs::symlink_metadata(&target).is_ok_and(|m| m.is_dir())
            || fs::metadata(&target).is_ok_and(|m| m.is_dir())
        {
            return send_error(conn, "is_a_directory", "target is a directory");
        }
        if !overwrite && fs::symlink_metadata(&target).is_ok() {
            return send_error(conn, "exists", "target exists and overwrite is false");
        }
        if let Err((code, msg)) = ensure_parent(parent, mkdirs) {
            return send_error(conn, code, &msg);
        }
    }
    let part = parent.join(format!(".{name}.azula-{upload}.part"));
    let target_s = target.to_string_lossy().into_owned();

    // Upload ownership record: the worker's own file.
    let rec_path = srv.uploads_dir().join(format!("{upload}.json"));
    match fs::read(&rec_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Upload>(&b).ok())
    {
        Some(u) if u.owner != owner || u.path != target_s => {
            return send_error(
                conn,
                "upload_conflict",
                "upload id is in use for another path or owner",
            );
        }
        Some(_) => {}
        None => {
            let rec = Upload {
                owner: owner.into(),
                path: target_s.clone(),
                part: part.to_string_lossy().into_owned(),
            };
            let b = serde_json::to_vec(&rec).unwrap_or_default();
            if let Err(e) = write_atomic(&rec_path, &b) {
                return io_err(conn, &e);
            }
        }
    }

    // The job user again, until only the record is left to remove.
    let user = match AsUser::enter(&id) {
        Ok(u) => u,
        Err(e) => return io_err(conn, &e),
    };
    let mut pf = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&part)
    {
        Ok(f) => f,
        Err(e) => return io_err(conn, &e),
    };
    let offset = match pf.metadata() {
        Ok(m) if m.is_file() => m.len(),
        Ok(_) => return send_error(conn, "io_error", "part file is not a regular file"),
        Err(e) => return io_err(conn, &e),
    };
    let mut hasher = match hash_prefix(&mut pf, offset) {
        Ok(h) => h,
        Err(e) => return io_err(conn, &e),
    };
    if let Err(e) = pf.seek(SeekFrom::Start(offset)) {
        return io_err(conn, &e);
    }
    if send(conn, json!({"t":"put_ready","offset":offset}), &[]).is_err() {
        return;
    }

    let mut size = offset;
    loop {
        let fr = match read_frame(reader) {
            Ok(Some(fr)) => fr,
            // Dropped before eof: keep the part file for resumption.
            Ok(None) | Err(_) => return,
        };
        match fr.t.as_str() {
            "data" => {
                if let Err(e) = pf.write_all(&fr.payload) {
                    return io_err(conn, &e);
                }
                hasher.update(&fr.payload);
                size += fr.payload.len() as u64;
            }
            "eof" => {
                let want_size = fr.header.get("size").and_then(Value::as_u64);
                let want_sha = fr.header.get("sha256").and_then(Value::as_str);
                let (Some(want_size), Some(want_sha)) = (want_size, want_sha) else {
                    return send_error(conn, "bad_request", "eof needs size and sha256");
                };
                let fail = |conn: &mut C, user: AsUser, code: &str, msg: String| {
                    let _ = fs::remove_file(&part);
                    drop(user);
                    let _ = fs::remove_file(&rec_path);
                    send_error(conn, code, &msg);
                };
                if want_size != size {
                    return fail(
                        conn,
                        user,
                        "size_mismatch",
                        format!("received {size} bytes, client says {want_size}"),
                    );
                }
                let got = hasher.clone().hex();
                if !got.eq_ignore_ascii_case(want_sha) {
                    return fail(
                        conn,
                        user,
                        "digest_mismatch",
                        format!("sha256 is {got}, client says {want_sha}"),
                    );
                }
                let finish = || -> io::Result<()> {
                    pf.set_permissions(fs::Permissions::from_mode(mode))?;
                    pf.sync_all()?;
                    if overwrite {
                        fs::rename(&part, &target)?;
                    } else {
                        fs::hard_link(&part, &target)?;
                        fs::remove_file(&part)?;
                    }
                    crate::util::fsync_dir(parent);
                    Ok(())
                };
                let finished = finish();
                drop(user);
                match finished {
                    Ok(()) => {
                        let _ = fs::remove_file(&rec_path);
                        let _ = send(
                            conn,
                            json!({"t":"put_ok","path":target_s,"size":size,"sha256":got}),
                            &[],
                        );
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        send_error(conn, "exists", "target exists and overwrite is false")
                    }
                    Err(e) => io_err(conn, &e),
                }
                return;
            }
            other => {
                return send_error(
                    conn,
                    "bad_request",
                    &format!("unexpected frame {other:?} during put"),
                )
            }
        }
    }
}

pub fn get<C: Write>(srv: &Arc<Server>, f: &Frame, conn: &mut C) {
    let s = |k: &str| f.header.get(k).and_then(Value::as_str);
    let (Some(owner), Some(path)) = (s("owner"), s("path")) else {
        return send_error(conn, "bad_request", "owner and path are required");
    };
    if owner.is_empty() {
        return send_error(conn, "bad_request", "owner is required");
    }
    let offset = f.header.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let etag = s("etag");
    let id = resolve(&srv.cfg.run_as);
    let target = match resolve_path(&id.home, path) {
        Ok(t) => t,
        Err(m) => return send_error(conn, "bad_request", &m),
    };
    // The job user reads it, to the end of the transfer.
    let _user = match AsUser::enter(&id) {
        Ok(u) => u,
        Err(e) => return io_err(conn, &e),
    };
    let md = match fs::metadata(&target) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return send_error(
                conn,
                "not_found",
                &format!("{}: no such file", target.display()),
            )
        }
        Err(e) => return io_err(conn, &e),
    };
    if !md.is_file() {
        return send_error(
            conn,
            "not_a_file",
            &format!(
                "{} is not a regular file (use -r for directories)",
                target.display()
            ),
        );
    }
    // O_NONBLOCK so a FIFO swapped in after the stat can't hang us.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&target)
    {
        Ok(f) => f,
        Err(e) => return io_err(conn, &e),
    };
    let md = match file.metadata() {
        Ok(m) if m.is_file() => m,
        Ok(_) => return send_error(conn, "not_a_file", "not a regular file"),
        Err(e) => return io_err(conn, &e),
    };
    let size = md.len();
    let cur_etag = format!(
        "{}:{}:{}:{}",
        md.dev(),
        md.ino(),
        size,
        md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128
    );
    if etag.is_some_and(|e| e != cur_etag) {
        return send_error(conn, "changed", "file changed since the transfer began");
    }
    if offset > size {
        return send_error(conn, "bad_request", "offset is past the end of the file");
    }
    let meta = json!({
        "t":"get_meta","path":target.to_string_lossy(),"size":size,
        "mode":md.mode() & 0o777,"etag":cur_etag
    });
    if send(conn, meta, &[]).is_err() {
        return;
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    while pos < size {
        let want = (size - pos).min(CHUNK as u64) as usize;
        let n = match file.read_at(&mut buf[..want], pos) {
            Ok(0) => {
                return send_error(conn, "io_error", "file shrank during transfer");
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return io_err(conn, &e),
        };
        hasher.update(&buf[..n]);
        if pos + n as u64 > offset {
            let skip = offset.saturating_sub(pos) as usize;
            if send(conn, json!({"t":"data"}), &buf[skip..n]).is_err() {
                return;
            }
        }
        pos += n as u64;
    }
    let _ = send(
        conn,
        json!({"t":"get_end","size":size,"sha256":hasher.hex()}),
        &[],
    );
}
