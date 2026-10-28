//! Reversible, opt-in per-user editor/shell integration.
use crate::domain::error::{Error, Result};
use crate::infrastructure::fsutil::{atomic_write, io_err};
use std::fs;
use std::path::{Path, PathBuf};

const PROFILE_START: &str = "# >>> ratriyx managed proxy >>>";
const PROFILE_END: &str = "# <<< ratriyx managed proxy <<<";
const ZED_MARK: &str = " // ratriyx-managed-proxy";

fn read(path: &Path) -> Result<String> {
    if path.exists() {
        fs::read_to_string(path).map_err(io_err)
    } else {
        Ok(String::new())
    }
}

fn save(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io_err)?;
    }
    atomic_write(path, text.as_bytes(), true)
}

/// Windows PowerShell 5.1 profile (powershell.exe).
pub fn profile_path() -> Result<PathBuf> {
    Ok(profile_at(&documents_dir()?, false))
}

/// PowerShell 7+ profile (pwsh.exe).
pub fn pwsh_path() -> Result<PathBuf> {
    Ok(profile_at(&documents_dir()?, true))
}

#[cfg(windows)]
fn documents_dir() -> Result<PathBuf> {
    crate::infrastructure::windows_documents::documents_dir()
}

#[cfg(not(windows))]
fn documents_dir() -> Result<PathBuf> {
    old_documents_dir()
}

fn old_documents_dir() -> Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .ok_or_else(|| Error::Config("USERPROFILE/HOME is missing".into()))?;
    Ok(PathBuf::from(home).join("Documents"))
}

fn profile_at(documents: &Path, pwsh: bool) -> PathBuf {
    documents
        .join(if pwsh {
            "PowerShell"
        } else {
            "WindowsPowerShell"
        })
        .join("Microsoft.PowerShell_profile.ps1")
}

fn legacy_path(pwsh: bool) -> Result<PathBuf> {
    Ok(profile_at(&old_documents_dir()?, pwsh))
}

pub fn zed_path() -> Result<PathBuf> {
    let app =
        std::env::var_os("APPDATA").ok_or_else(|| Error::Config("APPDATA is missing".into()))?;
    Ok(PathBuf::from(app).join("Zed").join("settings.json"))
}

fn managed_profile_block(port: u16) -> String {
    format!(
        r#"{PROFILE_START}
# Applies to NEW PowerShell shells. Missing proxy fails closed for proxy-aware clients.
$env:HTTP_PROXY = 'http://127.0.0.1:{port}'
$env:HTTPS_PROXY = 'http://127.0.0.1:{port}'
$env:ALL_PROXY = 'http://127.0.0.1:{port}'
$env:NO_PROXY = 'localhost,127.0.0.1,::1'
$ratriyxClient = [System.Net.Sockets.TcpClient]::new()
try {{
  $ratriyxClient.Connect('127.0.0.1', {port})
}} catch {{
  Write-Warning 'Ratriyx proxy 127.0.0.1:{port} is unavailable. Proxy-aware requests will fail until it starts.'
}} finally {{ $ratriyxClient.Dispose() }}
{PROFILE_END}
"#
    )
}

// v0.4's first profile generator. Keep this exact form for safe migration:
// only blocks written by Ratriyx may be removed from the old Documents path.
fn original_profile_block(port: u16) -> String {
    format!(
        r#"{PROFILE_START}
# Applies to NEW PowerShell shells only, and only while the proxy is listening.
$ratriyxClient = [System.Net.Sockets.TcpClient]::new()
try {{
  $ratriyxClient.Connect('127.0.0.1', {port})
  $env:HTTP_PROXY = 'http://127.0.0.1:{port}'
  $env:HTTPS_PROXY = 'http://127.0.0.1:{port}'
  $env:ALL_PROXY = 'http://127.0.0.1:{port}'
  $env:NO_PROXY = 'localhost,127.0.0.1,::1'
}} catch {{ }} finally {{ $ratriyxClient.Dispose() }}
{PROFILE_END}
"#
    )
}

fn managed_span(text: &str, port: u16) -> Result<Option<(usize, usize)>> {
    let begin = text.find(PROFILE_START);
    let end_marker = text.find(PROFILE_END);
    if begin.is_none() && end_marker.is_none() {
        return Ok(None);
    }
    let start = begin.ok_or_else(|| {
        Error::Config(
            "PowerShell profile has an orphaned Ratriyx end marker; refusing to edit".into(),
        )
    })?;
    if text[start + PROFILE_START.len()..].contains(PROFILE_START)
        || text.matches(PROFILE_END).count() != 1
    {
        return Err(Error::Config(
            "PowerShell profile has multiple Ratriyx markers; refusing to edit".into(),
        ));
    }
    for candidate in [managed_profile_block(port), original_profile_block(port)] {
        if text[start..].starts_with(&candidate) {
            return Ok(Some((start, start + candidate.len())));
        }
    }
    Err(Error::Config(
        "Ratriyx PowerShell block differs from the known template or uses another port; refusing to overwrite it".into()
    ))
}

fn remove_managed(text: &str, port: u16) -> Result<Option<String>> {
    let Some((begin, end)) = managed_span(text, port)? else {
        return Ok(None);
    };
    Ok(Some(format!("{}{}", &text[..begin], &text[end..])))
}

fn append_managed(text: &str, port: u16) -> String {
    let mut next = text.to_owned();
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(&managed_profile_block(port));
    next
}

/// Preserve the full previous profile before touching either profile during
/// a redirected-Documents migration. Never overwrite previous recovery copies.
fn migration_backup(path: &Path, content: &str) -> Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Config("invalid PowerShell profile name".into()))?;
    let backup = path.with_file_name(format!(
        "{}.ratriyx-before-migration.bak",
        name.to_string_lossy()
    ));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)
        .map_err(|e| {
            Error::Io(format!(
                "cannot create migration backup {}: {}",
                backup.display(),
                e.kind()
            ))
        })?;
    use std::io::Write as _;
    f.write_all(content.as_bytes()).map_err(io_err)?;
    f.sync_all().map_err(io_err)?;
    Ok(())
}

/// Redirect-aware enabling/disabling. Works with in-memory fixture paths in
/// tests; production passes the Windows known-folder and legacy default path.
fn change_profile_paths(current: &Path, legacy: &Path, enable: bool, port: u16) -> Result<String> {
    // Windows Documents redirects can be junctions rather than ordinary
    // paths. Avoid treating two aliases for one file as distinct profiles.
    let same_file = current == legacy
        || (current.exists()
            && legacy.exists()
            && matches!(
                (current.canonicalize(), legacy.canonicalize()),
                (Ok(a), Ok(b)) if a == b
            ));
    if same_file {
        return edit_profile(current, enable, port);
    }
    let current_text = read(current)?;
    let current_existed = current.exists();
    let legacy_text = read(legacy)?;
    let current_span = managed_span(&current_text, port)?;
    let legacy_span = managed_span(&legacy_text, port)?;
    if enable && current_span.is_some() && legacy_span.is_none() {
        return Ok(format!(
            "PowerShell profile already enabled at {}",
            current.display()
        ));
    }
    if !enable && current_span.is_none() && legacy_span.is_none() {
        return Err(Error::Config(
            "no Ratriyx block found in either PowerShell profile".into(),
        ));
    }
    let next_current = if enable {
        if current_span.is_some() {
            Some(current_text.clone())
        } else {
            Some(append_managed(&current_text, port))
        }
    } else {
        remove_managed(&current_text, port)?
    };
    let next_legacy = if legacy_span.is_some() {
        remove_managed(&legacy_text, port)?
    } else {
        None
    };
    // Snapshot the originals first so an interruption or a failed second
    // write can always be recovered without losing unrelated user scripts.
    if let Some(next) = &next_current {
        if legacy_span.is_some() && next != &current_text && current_existed {
            migration_backup(current, &current_text)?;
        }
    }
    if next_legacy.is_some() && legacy.exists() {
        migration_backup(legacy, &legacy_text)?;
    }
    let changed_current = next_current
        .as_ref()
        .is_some_and(|new| new != &current_text);
    if changed_current {
        save(current, next_current.as_ref().unwrap())?;
    }
    if let Some(next) = next_legacy {
        if let Err(e) = save(legacy, &next) {
            if changed_current {
                let _ = if current_existed {
                    save(current, &current_text)
                } else {
                    fs::remove_file(current).map_err(io_err)
                };
            }
            return Err(Error::Io(format!(
                "could not clean legacy PowerShell profile ({e}); backup retained. Check both profile paths before retrying"
            )));
        }
    }
    Ok(format!(
        "PowerShell profile {}: {}{}",
        if enable { "enabled" } else { "restored" },
        current.display(),
        if legacy_span.is_some() {
            " (old misplaced Ratriyx block cleaned)"
        } else {
            ""
        }
    ))
}

pub fn change_powershell_profile(pwsh: bool, enable: bool, port: u16) -> Result<String> {
    let current = if pwsh { pwsh_path()? } else { profile_path()? };
    let old = legacy_path(pwsh)?;
    change_profile_paths(&current, &old, enable, port)
}

pub fn edit_profile(path: &Path, enable: bool, port: u16) -> Result<String> {
    let old = read(path)?;
    let changed = if enable {
        if old.contains(PROFILE_START) || old.contains(PROFILE_END) {
            return Err(Error::Config(
                "managed PowerShell profile block already exists; disable it first".into(),
            ));
        }
        append_managed(&old, port)
    } else {
        remove_managed(&old, port)?
            .ok_or_else(|| Error::Config("no Ratriyx block found in PowerShell profile".into()))?
    };
    save(path, &changed)?;
    Ok(format!(
        "PowerShell profile {}: {}",
        if enable { "enabled" } else { "restored" },
        path.display()
    ))
}

pub fn edit_zed(path: &Path, enable: bool, port: u16) -> Result<String> {
    let old = read(path)?;
    let changed = if enable {
        if old.contains(ZED_MARK) {
            return Err(Error::Config(
                "Zed already contains a managed proxy entry".into(),
            ));
        }
        // Preserve arbitrary JSONC (including comments), but refuse to alter an
        // existing proxy key. We only insert immediately after the root brace.
        if old.contains("\"proxy\"") {
            return Err(Error::Config(
                "Zed already has a proxy setting; refusing to overwrite it".into(),
            ));
        }
        let base = if old.trim().is_empty() {
            "{}".to_string()
        } else {
            old
        };
        let brace = base
            .find('{')
            .ok_or_else(|| Error::Config("Zed settings have no root object".into()))?;
        if !base[brace..].contains('}') {
            return Err(Error::Config(
                "Zed settings lack a closing root brace".into(),
            ));
        }
        let rest = &base[brace + 1..];
        let has_more = !rest.trim_start().starts_with('}');
        let entry = format!(
            "\n  \"proxy\": \"http://127.0.0.1:{port}\"{}{}\n",
            if has_more { "," } else { "" },
            ZED_MARK
        );
        format!("{}{}{}", &base[..brace + 1], entry, rest)
    } else {
        if !old.contains(ZED_MARK) {
            return Err(Error::Config(
                "Zed has no Ratriyx-managed proxy entry".into(),
            ));
        }
        let line_start = old[..old.find(ZED_MARK).unwrap()]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let tail = &old[line_start..];
        let line_end = tail
            .find('\n')
            .map(|i| line_start + i + 1)
            .unwrap_or(old.len());
        let managed_line = &old[line_start..line_end];
        if !managed_line.contains("\"proxy\": \"http://127.0.0.1:") {
            return Err(Error::Config(
                "Zed managed entry has been edited; refusing automatic removal".into(),
            ));
        }
        // The inserted line has its own leading newline. Removing it as well
        // preserves the original JSONC bytes, including preexisting newlines.
        let remove_from = if line_start > 0 && old.as_bytes()[line_start - 1] == b'\n' {
            line_start - 1
        } else {
            line_start
        };
        format!("{}{}", &old[..remove_from], &old[line_end..])
    };
    save(path, &changed)?;
    Ok(format!(
        "Zed proxy {}: {}",
        if enable { "enabled" } else { "restored" },
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("ratriyx-desktop-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }
    #[test]
    fn profile_round_trip_preserves_existing_text() {
        let path = scratch("profile.ps1");
        fs::write(&path, "Write-Host 'existing'\n").unwrap();
        edit_profile(&path, true, 8119).unwrap();
        assert!(read(&path).unwrap().contains("TcpClient"));
        assert!(!read(&path).unwrap().contains("\n+"));
        assert!(edit_profile(&path, true, 8119).is_err());
        edit_profile(&path, false, 8119).unwrap();
        assert_eq!(read(&path).unwrap(), "Write-Host 'existing'\n");
    }
    #[test]
    fn redirected_documents_migrates_old_block_without_overwriting_user_profile() {
        let dir =
            std::env::temp_dir().join(format!("ratriyx-migration-{}-one", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let real = dir
            .join("OneDrive")
            .join("WindowsPowerShell")
            .join("profile.ps1");
        let old = dir
            .join("Documents")
            .join("WindowsPowerShell")
            .join("profile.ps1");
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        fs::write(&real, "# user's real profile\nWrite-Host 'keep me'\n").unwrap();
        fs::write(
            &old,
            format!(
                "Write-Host 'legacy untouched'\n{}",
                original_profile_block(8119)
            ),
        )
        .unwrap();
        let result = change_profile_paths(&real, &old, true, 8119).unwrap();
        assert!(result.contains("old misplaced Ratriyx block cleaned"));
        let current = read(&real).unwrap();
        assert!(current.contains("Write-Host 'keep me'"));
        assert!(current.contains("Proxy-aware requests will fail"));
        assert_eq!(read(&old).unwrap(), "Write-Host 'legacy untouched'\n");
        assert!(real
            .with_file_name("profile.ps1.ratriyx-before-migration.bak")
            .exists());
        assert!(old
            .with_file_name("profile.ps1.ratriyx-before-migration.bak")
            .exists());
        assert!(change_profile_paths(&real, &old, true, 8119)
            .unwrap()
            .contains("already enabled"));
        change_profile_paths(&real, &old, false, 8119).unwrap();
        assert_eq!(
            read(&real).unwrap(),
            "# user's real profile\nWrite-Host 'keep me'\n"
        );
        assert_eq!(read(&old).unwrap(), "Write-Host 'legacy untouched'\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_legacy_block_fails_before_modifying_either_profile() {
        let dir =
            std::env::temp_dir().join(format!("ratriyx-migration-{}-unsafe", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.ps1");
        let old = dir.join("legacy.ps1");
        fs::write(&real, "# personal contents\n").unwrap();
        fs::write(
            &old,
            original_profile_block(8119).replace("catch { }", "catch { Write-Host 'edited' }"),
        )
        .unwrap();
        assert!(change_profile_paths(&real, &old, true, 8119).is_err());
        assert_eq!(read(&real).unwrap(), "# personal contents\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabling_only_the_misplaced_profile_removes_only_managed_block() {
        let dir =
            std::env::temp_dir().join(format!("ratriyx-migration-{}-off", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.ps1");
        let old = dir.join("legacy.ps1");
        fs::write(&real, "Write-Host 'real'\n").unwrap();
        fs::write(
            &old,
            format!("Write-Host 'legacy'\n{}", original_profile_block(8119)),
        )
        .unwrap();
        change_profile_paths(&real, &old, false, 8119).unwrap();
        assert_eq!(read(&real).unwrap(), "Write-Host 'real'\n");
        assert_eq!(read(&old).unwrap(), "Write-Host 'legacy'\n");
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn zed_round_trip_preserves_existing_jsonc() {
        let path = scratch("zed.json");
        let original = "{\n  // user settings\n  \"theme\": \"Dark\"\n}\n";
        fs::write(&path, original).unwrap();
        edit_zed(&path, true, 8119).unwrap();
        assert!(read(&path)
            .unwrap()
            .contains("\"proxy\": \"http://127.0.0.1:8119\""));
        edit_zed(&path, false, 8119).unwrap();
        assert_eq!(read(&path).unwrap(), original);
    }
    #[test]
    fn zed_existing_proxy_is_not_overwritten() {
        let path = scratch("zed-existing.json");
        fs::write(&path, "{\"proxy\":\"http://old\"}").unwrap();
        assert!(edit_zed(&path, true, 8119).is_err());
        assert_eq!(read(&path).unwrap(), "{\"proxy\":\"http://old\"}");
    }
}
