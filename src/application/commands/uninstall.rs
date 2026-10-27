//! Explicit, per-dependency Windows cleanup. Nothing external is removed
//! merely because Ratriyx itself is being uninstalled.
use super::maintenance;
use crate::domain::error::{Error, Result};
use crate::infrastructure::config;
use crate::infrastructure::fsutil::io_err;
use crate::infrastructure::{managed, shell};
#[cfg(windows)]
use crate::infrastructure::{hash::sha256_hex, winmanaged as wm};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Choices {
    settings: bool,
    tor: bool,
    privoxy: bool,
}

fn owns(rec: &managed::Record, name: &str, source: &str) -> bool {
    rec.platform == "windows"
        && rec
            .dependencies
            .iter()
            .any(|dep| dep.name == name && dep.source == source)
}

fn ask<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, message: &str) -> Result<bool> {
    writer.write_all(message.as_bytes()).map_err(io_err)?;
    writer.flush().map_err(io_err)?;
    let mut answer = String::new();
    reader.read_line(&mut answer).map_err(io_err)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Running without flags asks separately about settings, Tor, and Privoxy.
/// --yes without explicit dependency flags removes only Ratriyx settings.
/// --remove-tor / --remove-privoxy are never implied by --yes.
pub fn run(yes: bool, remove_tor: bool, remove_privoxy: bool) -> Result<i32> {
    let state = shell::require_state_dir()?;
    let rec = managed::load(&state)?.unwrap_or_default();
    let owned_tor = owns(&rec, "tor", "official-download:tor-expert-bundle");
    let owned_privoxy = owns(&rec, "privoxy", "winget:Privoxy.Privoxy");
    say!("Uninstall preview: only Ratriyx-owned items can be removed.");
    say!("  Ratriyx settings/snapshots: optional");
    say!(
        "  Managed Tor bundle: {}",
        if owned_tor { "eligible (Ratriyx installed)" } else { "not owned; untouched" }
    );
    say!(
        "  Privoxy WinGet package: {}",
        if owned_privoxy { "eligible (Ratriyx installed)" } else { "not owned; untouched" }
    );
    say!("  Ratriyx executable: not removed by this command (use cargo uninstall ratriyx).");

    if remove_tor && !owned_tor {
        return Err(Error::Approval(
            "Tor is not recorded as Ratriyx-managed; refusing to remove it".into(),
        ));
    }
    if remove_privoxy && !owned_privoxy {
        return Err(Error::Approval(
            "Privoxy is not recorded as Ratriyx-installed; refusing WinGet uninstall".into(),
        ));
    }

    let selected = if yes {
        Choices {
            settings: true,
            tor: remove_tor,
            privoxy: remove_privoxy,
        }
    } else {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(Error::Approval(
                "interactive confirmation needs a terminal; use --yes for settings only, and additionally --remove-tor and/or --remove-privoxy for dependency removal".into(),
            ));
        }
        let mut input = io::stdin().lock();
        let mut output = io::stdout().lock();
        let settings = ask(
            &mut input,
            &mut output,
            "Remove Ratriyx settings and snapshots? [y/N]: ",
        )?;
        let tor = owned_tor
            && ask(
                &mut input,
                &mut output,
                "Stop and DELETE the Ratriyx-managed Tor bundle and its data? [y/N]: ",
            )?;
        let privoxy = owned_privoxy
            && ask(
                &mut input,
                &mut output,
                "Stop and UNINSTALL Ratriyx-installed Privoxy via WinGet? [y/N]: ",
            )?;
        Choices {
            settings,
            tor,
            privoxy,
        }
    };

    if selected == Choices::default() {
        say!("Uninstall cancelled; no changes were made.");
        return Ok(0);
    }

    #[cfg(windows)]
    {
        // Remove Privoxy before Tor so the managed HTTP listener never points
        // at a Tor process that was already intentionally removed.
        if selected.privoxy {
            remove_privoxy_owned(&state)?;
        }
        if selected.tor {
            remove_tor_owned(&state, &rec)?;
        }
    }
    #[cfg(not(windows))]
    {
        if selected.tor || selected.privoxy {
            return Err(Error::Config(
                "managed dependency removal is only implemented on Windows".into(),
            ));
        }
    }

    if selected.settings {
        maintenance::uninstall(true)?;
    } else if selected.tor || selected.privoxy {
        // A later interactive bare invocation should offer to configure
        // dependencies again, even if the user's other settings remain.
        let marker = state.join("first-run-v1");
        if marker.is_file() {
            fs::remove_file(&marker).map_err(io_err)?;
        }
    }
    say!("Uninstall selection completed. Ratriyx executable remains installed.");
    Ok(0)
}

#[cfg(windows)]
fn owned_paths() -> Result<(PathBuf, PathBuf)> {
    let base = wm::managed_base()
        .ok_or_else(|| Error::Config("LOCALAPPDATA unavailable; refusing cleanup".into()))?;
    let canonical_base = fs::canonicalize(&base).map_err(|e| {
        Error::Io(format!("cannot verify managed root {}: {e}", base.display()))
    })?;
    if fs::symlink_metadata(&base).map_err(io_err)?.file_type().is_symlink() {
        return Err(Error::Verification("managed dependency root is a symlink; refusing cleanup".into()));
    }
    Ok((base, canonical_base))
}

#[cfg(windows)]
fn remove_privoxy_owned(state: &Path) -> Result<()> {
    let rec = managed::load(state)?.ok_or_else(|| Error::Config("ownership record missing".into()))?;
    if !owns(&rec, "privoxy", "winget:Privoxy.Privoxy") {
        return Err(Error::Verification("Privoxy is not Ratriyx-owned".into()));
    }
    let (base, _) = owned_paths()?;
    let conf = base.join("privoxy.conf");
    if conf.exists() {
        let contents = fs::read_to_string(&conf).map_err(io_err)?;
        if contents != wm::privoxy_conf_text(8118, "127.0.0.1:9050") {
            return Err(Error::Verification(format!(
                "managed Privoxy config {} was modified; refusing automatic removal",
                conf.display()
            )));
        }
    }
    let pid = wm::pid_path(state, "privoxy");
    if pid.exists() {
        let exe = wm::find_privoxy_exe(&std::env::var_os("PATH").unwrap_or_default()).ok_or_else(|| {
            Error::Verification("cannot locate the exact Privoxy executable for PID identity verification".into())
        })?;
        say!("  Stopping Ratriyx-tracked Privoxy...");
        say!("{}", wm::stop_tracked_verified(&pid, &exe)?);
    }
    say!("  Uninstalling Ratriyx-installed Privoxy through WinGet...");
    let status = std::process::Command::new("winget.exe")
        .args([
            "uninstall",
            "--exact",
            "--id",
            wm::PRIVOXY_WINGET_ID,
            "--silent",
            "--accept-source-agreements",
        ])
        .status()
        .map_err(|e| Error::Io(format!("cannot run WinGet uninstall: {e}")))?;
    if !status.success() {
        return Err(Error::Io(format!(
            "WinGet Privoxy uninstall failed ({status}); ownership record preserved for retry"
        )));
    }
    if conf.is_file() {
        fs::remove_file(&conf).map_err(io_err)?;
    }
    managed::forget_dependency(state, "privoxy", &conf)?;
    say!("  [OK] Privoxy removed (Ratriyx-managed package only).");
    Ok(())
}

#[cfg(windows)]
fn remove_tor_owned(state: &Path, original_record: &managed::Record) -> Result<()> {
    let rec = managed::load(state)?.ok_or_else(|| Error::Config("ownership record missing".into()))?;
    if !owns(&rec, "tor", "official-download:tor-expert-bundle") {
        return Err(Error::Verification("Tor is not Ratriyx-owned".into()));
    }
    let (base, canonical_base) = owned_paths()?;
    let tor_dir = base.join("tor");
    let torrc = tor_dir.join("torrc");
    let pid = wm::pid_path(state, "tor");
    if tor_dir.exists() {
        if fs::symlink_metadata(&tor_dir).map_err(io_err)?.file_type().is_symlink()
            || !fs::canonicalize(&tor_dir).map_err(io_err)?.starts_with(&canonical_base)
        {
            return Err(Error::Verification(
                "managed Tor directory is a link or escapes its expected root; refusing removal".into()
            ));
        }
    }
    if pid.exists() {
        let exe = tor_dir.join("Tor").join("tor.exe");
        say!("  Stopping Ratriyx-tracked Tor...");
        say!("{}", wm::stop_tracked_verified(&pid, &exe)?);
    }
    if tor_dir.is_dir() {
        say!("  Removing Ratriyx-managed Tor files and data...");
        fs::remove_dir_all(&tor_dir).map_err(io_err)?;
    }
    // Only remove the downloaded archive when it matches the checksum Ratriyx
    // originally recorded. A changed file is left untouched.
    let archive_name = wm::TOR_BUNDLE_URL.rsplit('/').next().unwrap_or("");
    let archive = base.join(archive_name);
    if archive.is_file() {
        if let Some(dep) = original_record.dependencies.iter().find(|d| d.name == "tor") {
            let bytes = fs::read(&archive).map_err(io_err)?;
            if sha256_hex(&bytes) == dep.sha256 {
                fs::remove_file(&archive).map_err(io_err)?;
            }
        }
    }
    managed::forget_dependency(state, "tor", &torrc)?;
    say!("  [OK] Ratriyx-managed Tor bundle removed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn answer(input: &str) -> bool {
        let mut input = Cursor::new(input);
        let mut output = Vec::new();
        ask(&mut input, &mut output, "Remove component? [y/N]: ").unwrap()
    }

    #[test]
    fn prompt_is_explicit_and_defaults_to_no() {
        for input in ["", "\n", "n\n", "maybe\n"] {
            assert!(!answer(input));
        }
        assert!(answer("y\n"));
        assert!(answer("YES\n"));
    }

    #[test]
    fn ownership_requires_exact_install_source_and_windows() {
        let mut rec = managed::Record::default();
        rec.platform = "windows".into();
        rec.dependencies.push(managed::Dependency {
            name: "tor".into(),
            source: "official-download:tor-expert-bundle".into(),
            version: "15.0.25".into(),
            sha256: "abc".into(),
        });
        assert!(owns(&rec, "tor", "official-download:tor-expert-bundle"));
        assert!(!owns(&rec, "privoxy", "winget:Privoxy.Privoxy"));
        assert!(!owns(&rec, "tor", "winget:Tor.Tor"));
        rec.platform = "linux".into();
        assert!(!owns(&rec, "tor", "official-download:tor-expert-bundle"));
    }
}
