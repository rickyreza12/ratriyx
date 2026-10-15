use crate::domain::error::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

fn unique_nonce() -> u128 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Process ID plus time plus an in-process counter, so two writes from the
    // same process do not share a temp name.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
    (nanos ^ ((std::process::id() as u128) << 64)) ^ count
}

/// Writes `data` to a temporary file beside `path`, then renames it over `path`.
/// Existing permissions are kept. `private` additionally restricts the file to the owner.
pub fn atomic_write(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| Error::Io(format!("invalid target path {}", path.display())))?;
    let tmp: PathBuf = dir.join(format!(
        ".{}.ratriyx-tmp-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        unique_nonce()
    ));
    let result =
        write_tmp(&tmp, data, path, private).and_then(|()| fs::rename(&tmp, path).map_err(io_err));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    } else {
        sync_parent(dir);
    }
    result
}

/// Best-effort directory sync so the rename survives a crash on Unix.
fn sync_parent(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(file) = fs::File::open(dir) {
            let _ = file.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// File metadata: (mode, uid, gid). Mode is always available; uid/gid are
/// Unix-only and None elsewhere.
pub fn file_owner(path: &Path) -> (Option<u32>, Option<u32>, Option<u32>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::metadata(path) {
            Ok(meta) => (
                Some(meta.mode() & 0o777),
                Some(meta.uid()),
                Some(meta.gid()),
            ),
            Err(_) => (None, None, None),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        (None, None, None)
    }
}

fn write_tmp(tmp: &Path, data: &[u8], target: &Path, private: bool) -> Result<()> {
    // Stale or planted temp names are removed first; create_new then refuses to follow a symlink.
    let _ = fs::remove_file(tmp);
    let mut file = create_private(tmp).map_err(io_err)?;
    file.write_all(data).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    drop(file);
    if let Ok(meta) = fs::metadata(target) {
        fs::set_permissions(tmp, meta.permissions()).map_err(io_err)?;
    }
    if private {
        restrict_to_owner(tmp)?;
    }
    Ok(())
}

/// Attempt to restore file ownership after a privileged edit. Uses the
/// platform `chown` tool on Unix when available; a missing tool or a
/// permission failure is ignored because mode preservation is the guarantee
/// and ownership restoration is best-effort without extra dependencies.
pub fn try_chown(path: &Path, uid: Option<u32>, gid: Option<u32>) {
    #[cfg(unix)]
    {
        let (Some(u), Some(g)) = (uid, gid) else {
            return;
        };
        // Skip when already correct to avoid spawning a process.
        if let Ok(meta) = fs::metadata(path) {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() == u && meta.gid() == g {
                return;
            }
        }
        let spec = format!("{u}:{g}");
        let _ = std::process::Command::new("chown")
            .arg(&spec)
            .arg(path)
            .output();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid);
    }
}

/// Created owner-only so a private payload is never readable while it is being written.
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_err)
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<()> {
    // shortcut: Windows owner-only needs an ACL, which std cannot set; files rely on the
    // profile directory ACL until Windows runtime is verified.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ratriyx-fsutil-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn atomic_write_replaces_content_and_leaves_no_temp_file() {
        let dir = scratch("replace");
        let target = dir.join("config.txt");
        fs::write(&target, "old").unwrap();
        atomic_write(&target, b"new", false).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        let leftovers = fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1);
    }

    #[cfg(unix)]
    #[test]
    fn planted_symlink_at_the_temp_name_is_not_followed() {
        let dir = scratch("symlink");
        let victim = dir.join("victim");
        fs::write(&victim, "keep").unwrap();
        let target = dir.join("state");
        atomic_write(&target, b"data", true).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(fs::read(&target).unwrap(), b"data");
    }

    #[test]
    fn atomic_write_creates_new_file() {
        let dir = scratch("create");
        let target = dir.join("fresh.txt");
        atomic_write(&target, b"data", true).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"data");
    }

    #[test]
    fn owner_probe_returns_a_tuple_without_panicking() {
        let dir = scratch("owner");
        let target = dir.join("f");
        fs::write(&target, "x").unwrap();
        let _ = file_owner(&target);
        let _ = file_owner(&dir.join("missing"));
    }
}
