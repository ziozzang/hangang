//! Private configuration files, including Kubernetes ConfigMap and Secret
//! volumes: one acceptance rule for every configuration file the console
//! (and the registry it loads) reads.
use anyhow::{Context, Result, ensure};
use std::path::Path;

/// Whether a configuration file's owner and mode keep it private to this
/// process: (a) owned by the effective user with no group or other bits, or
/// (b) root-owned, in one of the process's groups (a Kubernetes ConfigMap or
/// Secret volume with `fsGroup`), with no write bits and no other bits (0440,
/// 0400). World-readable or writable files never qualify.
pub fn private_owner_mode(uid: u32, gid: u32, mode: u32, euid: u32, gids: &[u32]) -> bool {
    let mode = mode & 0o7777;
    (uid == euid && mode & 0o077 == 0)
        || (uid == 0 && gids.contains(&gid) && mode & 0o222 == 0 && mode & 0o007 == 0)
}

fn process_groups() -> Vec<u32> {
    // SAFETY: getegid/getgroups only write into the buffer of the stated size.
    let mut groups = vec![unsafe { libc::getegid() }];
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count > 0 {
        let mut more = vec![0 as libc::gid_t; count as usize];
        let n = unsafe { libc::getgroups(count, more.as_mut_ptr()) };
        if n > 0 {
            more.truncate(n as usize);
            groups.extend(more);
        }
    }
    groups
}

/// The real file behind `path`: `path` itself when it is not a symlink, or
/// the Kubernetes atomic-writer layout (`<dir>/<name>` -> `..data/<name>`,
/// `<dir>/..data` -> `..<version>`, a real directory in `<dir>`). Any other
/// symlink is refused, so a file cannot be pulled from outside its volume.
pub fn kubernetes_volume_file(path: &Path) -> Result<std::path::PathBuf> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_symlink() {
        return Ok(path.to_path_buf());
    }
    let name = path
        .file_name()
        .context("configuration path has no file name")?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    ensure!(
        std::fs::read_link(path)? == Path::new("..data").join(name),
        "configuration symlink is not the Kubernetes volume layout"
    );
    let version = std::fs::read_link(dir.join("..data"))?;
    let mut parts = version.components();
    let single = matches!(
        (parts.next(), parts.next()),
        (Some(std::path::Component::Normal(v)), None)
            if v.to_str().is_some_and(|v| v.starts_with("..") && v.len() > 2 && !v.contains('/'))
    );
    ensure!(
        single,
        "configuration volume ..data must name a version directory beside it"
    );
    let version_dir = dir.join(&version);
    ensure!(
        std::fs::symlink_metadata(&version_dir)?
            .file_type()
            .is_dir(),
        "configuration volume version is not a directory"
    );
    Ok(version_dir.join(name))
}

/// Open a private, bounded regular configuration file (see
/// `private_owner_mode` and `kubernetes_volume_file`).
pub fn open_private_config(path: &Path, limit: u64) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let real = kubernetes_volume_file(path)?;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&real)?;
    let meta = f.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= limit,
        "not a bounded regular file"
    );
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    ensure!(
        private_owner_mode(meta.uid(), meta.gid(), meta.mode(), euid, &process_groups()),
        "file is readable or writable beyond its owner (or a root-owned volume group)"
    );
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn owner_and_mode_rules() {
        let me = 1000;
        // (a) the process's own file, private.
        assert!(private_owner_mode(me, 50, 0o100600, me, &[50]));
        assert!(private_owner_mode(me, 50, 0o400, me, &[]));
        assert!(!private_owner_mode(me, 50, 0o640, me, &[]));
        assert!(!private_owner_mode(me, 50, 0o604, me, &[50]));
        // (b) root-owned volume file in one of our groups, no write, no other.
        assert!(private_owner_mode(0, 2000, 0o440, me, &[1000, 2000]));
        assert!(private_owner_mode(0, 2000, 0o400, me, &[2000]));
        assert!(
            !private_owner_mode(0, 2000, 0o444, me, &[2000]),
            "world-readable"
        );
        assert!(
            !private_owner_mode(0, 2000, 0o460, me, &[2000]),
            "group-writable"
        );
        assert!(
            !private_owner_mode(0, 2000, 0o640, me, &[2000]),
            "owner-writable"
        );
        assert!(
            !private_owner_mode(0, 3000, 0o440, me, &[2000]),
            "another group"
        );
        assert!(
            !private_owner_mode(1234, 2000, 0o440, me, &[2000]),
            "another non-root owner"
        );
    }

    fn write(path: &Path, mode: u32) {
        std::fs::write(path, b"{}").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn plain_files_and_the_kubernetes_volume_layout() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("sso.json");
        write(&plain, 0o600);
        assert!(open_private_config(&plain, 1024).is_ok());
        write(&plain, 0o644);
        assert!(open_private_config(&plain, 1024).is_err(), "world-readable");
        write(&plain, 0o600);
        assert!(open_private_config(&plain, 1).is_err(), "over the bound");

        // <vol>/..2026_10_17/sso.json, ..data -> ..2026_10_17, sso.json -> ..data/sso.json
        let vol = dir.path().join("vol");
        let version = vol.join("..2026_10_17_09_00_00.1");
        std::fs::create_dir_all(&version).unwrap();
        write(&version.join("sso.json"), 0o600);
        symlink("..2026_10_17_09_00_00.1", vol.join("..data")).unwrap();
        symlink("..data/sso.json", vol.join("sso.json")).unwrap();
        assert!(open_private_config(&vol.join("sso.json"), 1024).is_ok());
        write(&version.join("sso.json"), 0o644);
        assert!(open_private_config(&vol.join("sso.json"), 1024).is_err());
        write(&version.join("sso.json"), 0o600);

        // A symlink out of the volume, or ..data pointing elsewhere: refused.
        symlink(&plain, vol.join("escape.json")).unwrap();
        assert!(open_private_config(&vol.join("escape.json"), 1024).is_err());
        let other = dir.path().join("other");
        std::fs::create_dir_all(other.join("..x")).unwrap();
        write(&other.join("..x").join("sso.json"), 0o600);
        symlink(&version, other.join("..data")).unwrap();
        symlink("..data/sso.json", other.join("sso.json")).unwrap();
        assert!(
            open_private_config(&other.join("sso.json"), 1024).is_err(),
            "absolute ..data target"
        );
        let nested = dir.path().join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        symlink("../vol/..2026_10_17_09_00_00.1", nested.join("..data")).unwrap();
        symlink("..data/sso.json", nested.join("sso.json")).unwrap();
        assert!(
            open_private_config(&nested.join("sso.json"), 1024).is_err(),
            "..data escaping the volume"
        );
    }
}
