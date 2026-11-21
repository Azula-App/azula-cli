//! Directory trees for `push -r` / `pull -r`: building a tar locally, and
//! extracting one **defensively**, because the archive comes from a guest that
//! can produce anything. Extraction rejects absolute paths, `..`, links that
//! point outside the destination, entries under a symlinked parent, and
//! device/FIFO entries, and never writes outside the destination.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use tar::{Archive, Builder, EntryType};

/// Archive the contents of `dir` (as `./…`) into the file `out`. Symlinks are
/// stored as links, not followed.
pub fn build_tar(dir: &Path, out: &Path) -> Result<()> {
    let file = File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut b = Builder::new(file);
    b.follow_symlinks(false);
    b.append_dir_all(".", dir).with_context(|| format!("archiving {}", dir.display()))?;
    b.finish()?;
    Ok(())
}

/// The normal components of an archive path, or an error naming the problem.
fn clean_rel(path: &Path, what: &str) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            Component::ParentDir => bail!("{what} `{}` contains `..`", path.display()),
            Component::RootDir | Component::Prefix(_) => bail!("{what} `{}` is absolute", path.display()),
        }
    }
    Ok(out)
}

/// Resolve a symlink `target` as seen from the directory `from` (relative to
/// the destination root), purely lexically. Errors if it is absolute or
/// climbs out of the root.
fn resolve_link(from: &Path, target: &Path) -> Result<PathBuf> {
    let mut stack: Vec<_> = from.components().collect();
    for c in target.components() {
        match c {
            Component::Normal(_) => stack.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                if stack.pop().is_none() {
                    bail!("link target `{}` escapes the destination", target.display());
                }
            }
            Component::RootDir | Component::Prefix(_) => bail!("link target `{}` is absolute", target.display()),
        }
    }
    Ok(stack.iter().collect())
}

/// Make sure every ancestor of `rel` under `root` is a real directory (never a
/// symlink), creating missing ones when `create` is set.
fn check_ancestors(root: &Path, rel: &Path, create: bool) -> Result<()> {
    let mut cur = root.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    for c in &comps[..comps.len().saturating_sub(1)] {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => bail!("`{}` is under a symlinked parent", rel.display()),
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("`{}`: a parent is not a directory", rel.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !create {
                    bail!("`{}`: parent does not exist", rel.display());
                }
                fs::create_dir(&cur).with_context(|| format!("creating {}", cur.display()))?;
            }
            Err(e) => return Err(e).with_context(|| format!("checking {}", cur.display())),
        }
    }
    Ok(())
}

/// Remove an existing file or symlink at `path`, refusing to replace a directory.
fn clear_target(path: &Path, rel: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => bail!("`{}` exists as a directory", rel.display()),
        Ok(_) => fs::remove_file(path).with_context(|| format!("replacing {}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("checking {}", path.display())),
    }
}

/// Extract `archive` under `dest` (created if needed). Returns the number of
/// entries written. Fails on the first unsafe entry; everything before it stays.
pub fn extract_safe<R: Read>(archive: R, dest: &Path) -> Result<usize> {
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let root = fs::canonicalize(dest)?;
    let mut ar = Archive::new(archive);
    let mut written = 0;
    for entry in ar.entries().context("reading archive")? {
        let mut entry = entry.context("reading archive entry")?;
        let kind = entry.header().entry_type();
        let raw = entry.path().context("entry path")?.into_owned();
        let rel = clean_rel(&raw, "entry")?;
        match kind {
            EntryType::XGlobalHeader | EntryType::XHeader | EntryType::GNULongName | EntryType::GNULongLink => continue,
            EntryType::Char | EntryType::Block | EntryType::Fifo => bail!("entry `{}` is a device or FIFO", raw.display()),
            EntryType::Regular | EntryType::Directory | EntryType::Symlink | EntryType::Link => {}
            other => bail!("entry `{}` has unsupported type {:?}", raw.display(), other),
        }
        if rel.as_os_str().is_empty() {
            // "." itself.
            continue;
        }
        check_ancestors(&root, &rel, true)?;
        let target = root.join(&rel);
        let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
        match kind {
            EntryType::Directory => {
                match fs::symlink_metadata(&target) {
                    Ok(m) if m.file_type().is_symlink() => bail!("`{}` is a symlink where a directory is expected", rel.display()),
                    Ok(m) if m.is_dir() => {}
                    Ok(_) => bail!("`{}` exists and is not a directory", rel.display()),
                    Err(_) => fs::create_dir(&target).with_context(|| format!("creating {}", target.display()))?,
                }
                set_mode(&target, mode | 0o700)?;
            }
            EntryType::Regular => {
                clear_target(&target, &rel)?;
                let mut f = open_new(&target)?;
                io::copy(&mut entry, &mut f).with_context(|| format!("writing {}", target.display()))?;
                drop(f);
                set_mode(&target, mode)?;
            }
            EntryType::Symlink => {
                let link = entry.link_name()?.ok_or_else(|| anyhow!("symlink `{}` has no target", raw.display()))?.into_owned();
                // Must stay inside the destination when resolved from its own directory.
                resolve_link(rel.parent().unwrap_or(Path::new("")), &link)?;
                clear_target(&target, &rel)?;
                make_symlink(&link, &target)?;
            }
            EntryType::Link => {
                let name = entry.link_name()?.ok_or_else(|| anyhow!("hard link `{}` has no target", raw.display()))?.into_owned();
                let src_rel = clean_rel(&name, "hard link target")?;
                check_ancestors(&root, &src_rel, false)?;
                let src = root.join(&src_rel);
                match fs::symlink_metadata(&src) {
                    Ok(m) if m.is_file() => {}
                    _ => bail!("hard link `{}` points at `{}`, which is not a file in the destination", raw.display(), name.display()),
                }
                clear_target(&target, &rel)?;
                fs::hard_link(&src, &target).with_context(|| format!("linking {}", target.display()))?;
            }
            _ => unreachable!("filtered above"),
        }
        written += 1;
    }
    Ok(written)
}

fn open_new(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path).with_context(|| format!("creating {}", path.display()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn make_symlink(link: &Path, at: &Path) -> Result<()> {
    std::os::unix::fs::symlink(link, at).with_context(|| format!("creating symlink {}", at.display()))
}

#[cfg(not(unix))]
fn make_symlink(_: &Path, _: &Path) -> Result<()> {
    bail!("symlinks in archives are not supported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tar::Header;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("azula-tar-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// A raw header: `Header::set_path` refuses `..` and absolute names, which
    /// is exactly what a hostile archive would contain, so write the bytes.
    fn raw_entry(name: &str, kind: EntryType, link: Option<&str>, body: &[u8]) -> Vec<u8> {
        let mut h = Header::new_old();
        h.set_entry_type(kind);
        h.set_mode(0o644);
        h.set_size(body.len() as u64);
        {
            let old = h.as_old_mut();
            old.name[..name.len()].copy_from_slice(name.as_bytes());
            if let Some(l) = link {
                old.linkname[..l.len()].copy_from_slice(l.as_bytes());
            }
        }
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        out.extend_from_slice(body);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut a: Vec<u8> = entries.concat();
        a.extend(vec![0u8; 1024]);
        a
    }

    fn rejects(name: &str, entries: Vec<Vec<u8>>, needle: &str) {
        let d = tmp(name);
        let dest = d.join("dest");
        let err = extract_safe(&archive(&entries)[..], &dest).expect_err(name);
        assert!(format!("{err:#}").contains(needle), "{name}: {err:#}");
        // Nothing escaped: the only thing in the sandbox dir is `dest`.
        let siblings: Vec<_> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(siblings, vec![std::ffi::OsString::from("dest")], "{name}: wrote outside dest");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn malicious_archives_are_rejected() {
        rejects("dotdot", vec![raw_entry("../escape.txt", EntryType::Regular, None, b"x")], "`..`");
        rejects("nested-dotdot", vec![raw_entry("a/../../escape.txt", EntryType::Regular, None, b"x")], "`..`");
        rejects("absolute", vec![raw_entry("/tmp/azula-abs", EntryType::Regular, None, b"x")], "absolute");
        rejects("symlink-abs", vec![raw_entry("l", EntryType::Symlink, Some("/etc"), b"")], "absolute");
        rejects("symlink-escape", vec![raw_entry("l", EntryType::Symlink, Some("../.."), b"")], "escapes");
        rejects("symlink-escape-deep", vec![raw_entry("a/b/l", EntryType::Symlink, Some("../../.."), b"")], "escapes");
        rejects("fifo", vec![raw_entry("p", EntryType::Fifo, None, b"")], "device or FIFO");
        rejects("chardev", vec![raw_entry("c", EntryType::Char, None, b"")], "device or FIFO");
        rejects("blockdev", vec![raw_entry("b", EntryType::Block, None, b"")], "device or FIFO");
        rejects("hardlink-escape", vec![raw_entry("h", EntryType::Link, Some("../secret"), b"")], "`..`");
        rejects("hardlink-missing", vec![raw_entry("h", EntryType::Link, Some("nothing"), b"")], "not a file");
    }

    #[test]
    fn entry_under_a_symlinked_parent_is_rejected() {
        // A legal in-tree symlink, then a write *through* it.
        let d = tmp("symparent");
        let dest = d.join("dest");
        let a = archive(&[
            raw_entry("real/", EntryType::Directory, None, b""),
            raw_entry("link", EntryType::Symlink, Some("real"), b""),
            raw_entry("link/pwned.txt", EntryType::Regular, None, b"x"),
        ]);
        let err = extract_safe(&a[..], &dest).expect_err("must reject");
        assert!(format!("{err:#}").contains("symlinked parent"), "{err:#}");
        assert!(!dest.join("real/pwned.txt").exists(), "nothing written through the link");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn partial_extraction_before_a_bad_entry_stays_inside_dest() {
        let d = tmp("partial");
        let dest = d.join("dest");
        let a = archive(&[raw_entry("ok.txt", EntryType::Regular, None, b"fine"), raw_entry("../bad.txt", EntryType::Regular, None, b"no")]);
        assert!(extract_safe(&a[..], &dest).is_err());
        assert_eq!(fs::read(dest.join("ok.txt")).unwrap(), b"fine");
        assert!(!d.join("bad.txt").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_benign_tree_round_trips_with_links_and_modes() {
        let d = tmp("benign");
        let src = d.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("sub/b.sh"), b"#!/bin/sh\n").unwrap();
        set_mode(&src.join("sub/b.sh"), 0o755).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("../a.txt", src.join("sub/up")).unwrap();
        let tarball = d.join("t.tar");
        build_tar(&src, &tarball).unwrap();
        let dest = d.join("out");
        let n = extract_safe(File::open(&tarball).unwrap(), &dest).unwrap();
        assert!(n >= 4, "{n}");
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(dest.join("sub/b.sh")).unwrap().permissions().mode() & 0o777, 0o755);
            assert_eq!(fs::read_link(dest.join("sub/up")).unwrap(), PathBuf::from("../a.txt"));
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn link_resolution_is_lexical() {
        assert!(resolve_link(Path::new("a/b"), Path::new("../x")).is_ok());
        assert!(resolve_link(Path::new("a/b"), Path::new("../../x")).is_ok());
        assert!(resolve_link(Path::new("a/b"), Path::new("../../../x")).is_err());
        assert!(resolve_link(Path::new(""), Path::new("..")).is_err());
        assert!(resolve_link(Path::new(""), Path::new("/x")).is_err());
    }
}
