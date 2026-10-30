use crate::application::recovery;
use crate::domain::error::{Error, Result};
use crate::domain::route::{Mode, PROXY_VARS};
use crate::infrastructure::config::{self, Config};
use crate::infrastructure::fsutil;
use crate::infrastructure::managed;
use crate::infrastructure::privoxy;
use crate::infrastructure::service;
use crate::infrastructure::shell;
use crate::infrastructure::winpkg;
use crate::interface::cli::ShellKind;
use crate::interface::diagnostics;
use crate::interface::setup;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Managed setup: configure the Privoxy rule and start missing services, then
/// verify. Package installation is per-platform work (T305-T307): missing
/// binaries stop here with the exact manual step instead of guessing.
pub fn setup_install(cfg: &Config, yes: bool) -> Result<i32> {
    let path_var = env::var_os("PATH").unwrap_or_default();
    let facts = setup::gather(&path_var, cfg);
    let dir = shell::require_state_dir()?;
    if !facts.curl_installed {
        // Built-in curl.exe is preferred on Windows; only a missing curl takes
        // the managed path, and only on Windows where the source is verified.
        if !cfg!(windows) {
            return Err(Error::Config(
                "curl is required for verification; install it, then re-run".into(),
            ));
        }
        let actions = winpkg::plan_for("curl", false, Some("cURL.cURL"), None);
        if !yes {
            return Err(Error::Approval(format!(
                "managed setup would:\n  {}\nre-run with --install --yes to approve",
                winpkg::describe(&actions).join("\n  ")
            )));
        }
        for action in &actions {
            winpkg::execute(action, &dir)?;
        }
        managed::stamp(&dir)?;
        managed::record_dependency(
            &dir,
            "curl",
            "winget:cURL.cURL",
            "unknown",
            "package-manager",
        )?;
        say!("installed curl through WinGet");
    }
    #[cfg(windows)]
    {
        setup_install_managed_windows(cfg, &facts, yes, &dir)
    }
    #[cfg(not(windows))]
    {
        if !facts.tor_installed {
            return Err(Error::Config(
                "Tor is not installed; install Tor using your package manager, then retry".into(),
            ));
        }
        let socks_addr = cfg.tor_socks_addr();
        let was_running = crate::infrastructure::network::socks5_greeting(&socks_addr).is_ok();
        if !was_running {
            if !yes {
                return Err(Error::Approval(
                    "setup would start Tor; re-run with --install --yes to approve".into(),
                ));
            }
            service::control("start", service::TOR_INSTANCE, true)?;
        }
        let result = (|| -> Result<i32> {
            let socks = socks_addr
                .parse()
                .map_err(|_| Error::Config("invalid Tor SOCKS5 socket address".into()))?;
            let proxy = crate::infrastructure::embedded_proxy::EmbeddedProxy::start(socks)?;
            let mut probe_cfg = cfg.clone();
            probe_cfg.proxy_host = proxy.address().ip().to_string();
            probe_cfg.proxy_port = proxy.address().port();
            if let Some(reason) = diagnostics::verify_route_with_timeout(&probe_cfg, 30) {
                return Err(Error::Verification(format!(
                    "embedded Tor route could not be verified: {reason}"
                )));
            }
            say!("setup: Tor route verified through embedded Rust proxy (IsTor=true)");
            Ok(0)
        })();
        if result.is_err() && !was_running {
            let _ = service::control("stop", service::TOR_INSTANCE, true);
        }
        result
    }
}

/// Windows managed install (M005-M008): downloads pinned official artifacts,
/// writes Ratriyx-owned configs, runs tracked daemon processes, verifies,
/// and rolls back on failure. Only runs when binaries are missing; healthy
/// existing installations never reach here.
#[cfg(windows)]
fn setup_install_managed_windows(
    cfg: &Config,
    facts: &setup::SetupFacts,
    yes: bool,
    dir: &Path,
) -> Result<i32> {
    if !yes {
        return setup_install_managed_windows_inner(cfg, facts, false, dir);
    }
    let result = crate::interface::installer::with_dashboard(|| {
        setup_install_managed_windows_inner(cfg, facts, true, dir)
    });
    if matches!(result, Ok(0)) {
        say!("setup: managed Tor and embedded proxy verified, IsTor=true");
    }
    result
}

#[cfg(windows)]
fn setup_install_managed_windows_inner(
    cfg: &Config,
    _facts: &setup::SetupFacts,
    yes: bool,
    dir: &Path,
) -> Result<i32> {
    use crate::infrastructure::winmanaged as wm;
    let base = wm::managed_base()
        .ok_or_else(|| Error::Config("cannot find LOCALAPPDATA for managed Tor setup".into()))?;
    if cfg.tor_socks_host != "127.0.0.1" {
        return Err(Error::Config(
            "managed Tor requires tor.socks_host = 127.0.0.1".into(),
        ));
    }
    let tor_dir = base.join("tor");
    let data_dir = tor_dir.join("Data");
    let torrc = tor_dir.join("torrc");
    let tor_exe = tor_dir.join("Tor").join("tor.exe");
    let tor_present = tor_exe.is_file() && torrc.is_file();
    if tor_dir.exists() && !tor_present {
        return Err(Error::Verification(format!(
            "Ratriyx Tor directory {} is incomplete; refusing to overwrite it",
            tor_dir.display()
        )));
    }
    if tor_present {
        let existing = fs::read_to_string(&torrc).map_err(fsutil::io_err)?;
        if existing != wm::torrc_text(&data_dir, cfg.tor_socks_port, cfg.tor_control_port) {
            return Err(Error::Verification(
                "managed Tor configuration was changed; refusing to overwrite it".into(),
            ));
        }
    }
    let socks_addr = cfg.tor_socks_addr();
    if crate::infrastructure::network::socks5_greeting(&socks_addr).is_ok() {
        let mut probe_cfg = cfg.clone();
        let socks = socks_addr
            .parse()
            .map_err(|_| Error::Config("invalid managed Tor SOCKS5 socket address".into()))?;
        let proxy = crate::infrastructure::embedded_proxy::EmbeddedProxy::start(socks)?;
        probe_cfg.proxy_host = proxy.address().ip().to_string();
        probe_cfg.proxy_port = proxy.address().port();
        return match diagnostics::verify_route_with_timeout(&probe_cfg, 15) {
            None => {
                say!("setup: Tor is already running; embedded route verified (IsTor=true)");
                Ok(0)
            }
            Some(reason) => Err(Error::Verification(format!(
                "SOCKS5 is listening but its Tor exit could not be verified: {reason}"
            ))),
        };
    }
    let install_tor = !tor_present;
    let mut plan = Vec::new();
    if install_tor {
        plan.push(format!(
            "download pinned Tor {} and verify its checksum",
            wm::TOR_BUNDLE_VERSION
        ));
        plan.push("extract Tor and write the owned loopback torrc".to_string());
    } else {
        plan.push("reuse the existing managed Tor bundle".into());
    }
    plan.push("start managed Tor and wait for 100% bootstrap".into());
    plan.push("verify the route through a temporary embedded Rust HTTP proxy".into());
    if !yes {
        return Err(Error::Approval(format!(
            "managed setup would:\n  {}\nre-run with --install --yes to approve",
            plan.join("\n  ")
        )));
    }

    let total = if install_tor { 4 } else { 2 };
    let mut stages = Vec::new();
    if install_tor {
        stages.push("Downloading and verifying Tor".into());
        stages.push("Extracting Tor and writing configuration".into());
    }
    stages.push("Starting managed Tor and waiting for bootstrap".into());
    stages.push("Verifying IsTor through embedded proxy".into());
    crate::interface::installer::plan(stages);
    let mut step = 0usize;
    crate::interface::terminal::install_header();
    macro_rules! stage {
        ($message:expr) => {{
            step += 1;
            crate::interface::terminal::install_stage(step, total, $message);
        }};
    }
    if install_tor {
        stage!("Downloading and verifying Tor");
        let bundle = winpkg::execute(
            &winpkg::Action::Fetch {
                url: wm::TOR_BUNDLE_URL.into(),
                sha256: wm::TOR_BUNDLE_SHA256.into(),
            },
            &base,
        )?;
        crate::interface::terminal::install_done("Tor bundle checksum verified");
        stage!("Extracting Tor and writing configuration");
        if let Err(error) = (|| -> Result<()> {
            wm::extract_bundle(&bundle.path, &tor_dir)?;
            fs::create_dir_all(&data_dir).map_err(fsutil::io_err)?;
            fs::write(
                &torrc,
                wm::torrc_text(&data_dir, cfg.tor_socks_port, cfg.tor_control_port),
            )
            .map_err(fsutil::io_err)?;
            managed::stamp(dir)?;
            managed::record_dependency(
                dir,
                "tor",
                "official-download:tor-expert-bundle",
                wm::TOR_BUNDLE_VERSION,
                wm::TOR_BUNDLE_SHA256,
            )?;
            managed::record_file(dir, &torrc, "", &PathBuf::new())?;
            Ok(())
        })() {
            if !torrc.exists() {
                let _ = fs::remove_dir_all(&tor_dir);
            }
            return Err(error);
        }
        crate::interface::terminal::install_done("Managed Tor files extracted");
    }
    stage!("Starting managed Tor and waiting for bootstrap");
    wm::ensure_managed_tor(cfg)?;
    crate::interface::terminal::install_done("Tor SOCKS5 available and bootstrap complete");

    stage!("Verifying IsTor through embedded proxy");
    let socks = socks_addr
        .parse()
        .map_err(|_| Error::Config("invalid managed Tor SOCKS5 socket address".into()))?;
    let proxy = crate::infrastructure::embedded_proxy::EmbeddedProxy::start(socks)?;
    let mut probe_cfg = cfg.clone();
    probe_cfg.proxy_host = proxy.address().ip().to_string();
    probe_cfg.proxy_port = proxy.address().port();
    match diagnostics::verify_route_with_timeout(&probe_cfg, 30) {
        None => {
            crate::interface::terminal::install_done("Embedded Tor route verified (IsTor=true)");
            crate::interface::terminal::install_success(total);
            Ok(0)
        }
        Some(reason) => {
            let pid_file = wm::pid_path(dir, "tor");
            if let Err(cleanup) = wm::stop_tracked_verified(&pid_file, &tor_exe, &torrc) {
                return Err(Error::Verification(format!(
                    "IsTor verification failed ({reason}); managed Tor cleanup also failed ({cleanup})"
                )));
            }
            Err(Error::Verification(format!(
                "IsTor verification failed ({reason}); newly started managed Tor was stopped"
            )))
        }
    }
}

pub fn recover(cfg: &Config, target: Mode, apply: bool, yes: bool) -> Result<i32> {
    if target == Mode::Direct {
        let stale = PROXY_VARS
            .iter()
            .filter(|name| env::var_os(name).is_some())
            .map(|name| name.to_string())
            .collect();
        let plan = recovery::plan(
            target,
            &recovery::Facts {
                stale_proxy_vars: stale,
                tor_running: false,
                privoxy_running: false,
                forwarding_present: false,
                istor: None,
            },
        );
        show!("{}", recovery::render(&plan));
        if apply {
            for line in recovery::apply(&plan, yes)? {
                say!("{line}");
            }
        }
        return Ok(0);
    }
    if apply {
        if !yes {
            return Err(Error::Approval(
                "starting Tor requires --apply --yes".into(),
            ));
        }
        #[cfg(windows)]
        crate::infrastructure::winmanaged::ensure_managed_tor(cfg)?;
        #[cfg(not(windows))]
        if crate::infrastructure::network::socks5_greeting(&cfg.tor_socks_addr()).is_err() {
            service::control("start", service::TOR_INSTANCE, true)?;
        }
    }
    let socks = cfg
        .tor_socks_addr()
        .parse()
        .map_err(|_| Error::Config("invalid Tor SOCKS5 socket address".into()))?;
    let proxy = crate::infrastructure::embedded_proxy::EmbeddedProxy::start(socks)?;
    let mut probe_cfg = cfg.clone();
    probe_cfg.proxy_host = proxy.address().ip().to_string();
    probe_cfg.proxy_port = proxy.address().port();
    match diagnostics::verify_tor_exit_ip(&probe_cfg, 15) {
        Ok(ip) => {
            say!("Tor recovery: embedded proxy verified (IsTor=true)");
            if let Some(ip) = ip {
                say!("Tor exit IP: {ip}");
            }
            say!("launch: ratriyx run --opencode --mode tor");
            Ok(0)
        }
        Err(reason) => {
            say!("Tor recovery: not verified ({reason})");
            say!("next: ratriyx setup --dry-run");
            Ok(1)
        }
    }
}

pub fn uninstall(yes: bool) -> Result<i32> {
    uninstall_from(config::config_file(), shell::state_dir(), yes)
}

fn uninstall_from(config: Option<PathBuf>, state: Option<PathBuf>, yes: bool) -> Result<i32> {
    let mut owned: Vec<PathBuf> = Vec::new();
    if let Some(path) = config.filter(|p| p.exists()) {
        owned.push(path);
    }
    if let Some(dir) = state {
        // Retain the record and tracked process IDs while any managed
        // dependency still exists. Otherwise a regular Ratriyx uninstall
        // would erase the proof needed to remove it safely later.
        let retain_ownership = managed::load(&dir)?.is_some_and(|rec| {
            !rec.dependencies.is_empty() || !rec.files.is_empty() || !rec.services.is_empty()
        });
        for path in owned_in_state_dir(&dir) {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if retain_ownership && (name == managed::RECORD_NAME || name.ends_with(".pid")) {
                continue;
            }
            owned.push(path);
        }
        if retain_ownership {
            say!("Managed ownership record and PID files retained for later dependency removal.");
        }
    }
    owned.sort();
    owned.dedup();
    if owned.is_empty() {
        say!("nothing owned by ratriyx to remove");
        return Ok(0);
    }
    for path in &owned {
        say!("owned: {}", path.display());
    }
    say!("Tor, Privoxy, and system files are never touched by uninstall.");
    if !yes {
        return Err(Error::Approval(
            "re-run with --yes to remove the files listed above".into(),
        ));
    }
    for path in owned {
        fs::remove_file(&path).map_err(fsutil::io_err)?;
        say!("removed {}", path.display());
    }
    Ok(0)
}

/// Ratriyx-owned files inside one state directory: default snapshots,
/// per-session snapshots, the rotate marker, and the ownership record.
fn owned_in_state_dir(dir: &Path) -> Vec<PathBuf> {
    let mut owned = Vec::new();
    for kind in [
        ShellKind::Bash,
        ShellKind::Zsh,
        ShellKind::Fish,
        ShellKind::PowerShell,
    ] {
        let snapshot = shell::snapshot_path(dir, kind);
        if snapshot.exists() {
            owned.push(snapshot);
        }
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("env-snapshot-") {
                owned.push(entry.path());
            }
        }
    }
    for name in ["rotate.last", "first-run-v1", managed::RECORD_NAME] {
        let path = dir.join(name);
        if path.exists() {
            owned.push(path);
        }
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".pid") {
                owned.push(entry.path());
            }
        }
    }
    owned
}

/// Removes only Ratriyx-recorded managed dependencies: restores recorded
/// files from their backups and stops recorded services. Pre-existing
/// installations are never recorded, so they are never touched here.
pub fn uninstall_remove_managed(yes: bool) -> Result<i32> {
    let dir = shell::require_state_dir()?;
    let Some(rec) = managed::load(&dir)? else {
        say!("no managed dependencies recorded");
        return Ok(0);
    };
    if !rec.dependencies.is_empty() {
        return Err(Error::Approval(
            "Ratriyx-managed dependencies are still recorded. Use interactive 'ratriyx uninstall' to remove Tor/Privoxy first; refusing to discard their ownership record".into(),
        ));
    }
    for f in &rec.files {
        say!("managed file: {} (backup {})", f.path, f.backup);
    }
    for s in &rec.services {
        say!("managed service: {s}");
    }
    if !yes {
        return Err(Error::Approval(
            "re-run with --remove-managed --yes to restore files and stop recorded services".into(),
        ));
    }
    for line in restore_recorded_files(&dir, &rec.files)? {
        say!("{line}");
    }
    for unit in &rec.services {
        say!("{}", service::control("stop", unit, true)?);
    }
    fs::remove_file(managed::record_path(&dir)).map_err(fsutil::io_err)?;
    say!("managed record removed");
    Ok(0)
}

fn restore_recorded_files(dir: &Path, files: &[managed::ManagedFile]) -> Result<Vec<String>> {
    let _ = dir;
    let mut out = Vec::new();
    for f in files {
        let path = PathBuf::from(&f.path);
        if f.backup.is_empty() {
            // Created by Ratriyx, not edited: removal is the rollback.
            fs::remove_file(&path).map_err(fsutil::io_err)?;
            out.push(format!("removed created {}", path.display()));
            continue;
        }
        let backup = PathBuf::from(&f.backup);
        out.push(privoxy::restore_file(&path, &backup, true)?);
    }
    Ok(out)
}

pub fn config_migrate(yes: bool) -> Result<i32> {
    let legacy = config::legacy_config_file()
        .ok_or_else(|| Error::Config("cannot find the legacy config; set HOME".into()))?;
    let target = config::config_file()
        .ok_or_else(|| Error::Config("cannot find the ratriyx config; set HOME".into()))?;
    if yes {
        say!("{}", config::migrate(&legacy, &target)?);
    } else {
        say!("{}", config::migration_preview(&legacy, &target)?);
        say!("preview only; re-run with --yes to copy");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::hash::sha256_hex;

    fn state_scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ratriyx-uninstall-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn state_listing_finds_snapshots_rotate_marker_and_record() {
        let dir = state_scratch("list");
        fs::write(dir.join("env-snapshot.bash"), "x").unwrap();
        fs::write(dir.join("env-snapshot-term-a.bash"), "x").unwrap();
        fs::write(dir.join("rotate.last"), "1").unwrap();
        fs::write(dir.join(managed::RECORD_NAME), "version = 1\n").unwrap();
        fs::write(dir.join("other.txt"), "x").unwrap();
        let owned = owned_in_state_dir(&dir);
        assert_eq!(owned.len(), 4);
        assert!(owned.iter().all(|p| p.starts_with(&dir)));
    }

    #[test]
    fn recorded_file_restores_from_its_backup() {
        let dir = state_scratch("restore");
        let path = dir.join("privoxy.conf");
        let original = "listen-address 127.0.0.1:8118\n";
        fs::write(&path, original).unwrap();
        let cfg = Config {
            privoxy_config: path.to_string_lossy().to_string(),
            ..Config::default()
        };
        privoxy::configure_file_for(&path, &cfg.desired_rule(), false, true).unwrap();
        let backup = privoxy::latest_backup(&path).unwrap();
        let current = fs::read(&path).unwrap();
        managed::record_file(&dir, &path, &sha256_hex(&current), &backup).unwrap();
        let rec = managed::load(&dir).unwrap().unwrap();
        let out = restore_recorded_files(&dir, &rec.files).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn settings_uninstall_preserves_managed_dependency_record() {
        let home = state_scratch("keep-managed");
        let state = home.join("state");
        fs::create_dir_all(&state).unwrap();
        managed::record_dependency(
            &state,
            "tor",
            "official-download:tor-expert-bundle",
            "15.0.25",
            "known",
        )
        .unwrap();
        let marker = state.join("first-run-v1");
        let pid = state.join("tor.pid");
        fs::write(&marker, "configured").unwrap();
        fs::write(&pid, "4242").unwrap();
        assert!(uninstall_from(None, Some(state.clone()), true).is_ok());
        assert!(!marker.exists());
        assert!(managed::record_path(&state).exists());
        assert!(pid.exists());
        assert_eq!(
            managed::load(&state).unwrap().unwrap().dependencies.len(),
            1
        );
    }

    #[test]
    fn uninstall_from_temp_dirs_removes_only_owned_files() {
        let home = state_scratch("from");
        let state = home.join("state");
        fs::create_dir_all(&state).unwrap();
        let snap = state.join("env-snapshot.bash");
        fs::write(&snap, "x").unwrap();
        let keep = home.join("keep.txt");
        fs::write(&keep, "x").unwrap();
        assert!(uninstall_from(None, Some(state.clone()), true).is_ok());
        assert!(!snap.exists());
        assert!(keep.exists());
    }
}
