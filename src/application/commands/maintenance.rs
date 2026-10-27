use crate::application::recovery;
use crate::domain::error::{Error, Result};
use crate::domain::route::{Mode, PROXY_VARS};
use crate::infrastructure::config::{self, Config};
use crate::infrastructure::fsutil;
use crate::infrastructure::hash::sha256_hex;
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
    if !facts.tor_installed || !facts.privoxy_installed {
        #[cfg(windows)]
        {
            return setup_install_managed_windows(cfg, &facts, yes, &dir);
        }
        #[cfg(not(windows))]
        {
            for (present, name) in [
                (facts.tor_installed, "tor"),
                (facts.privoxy_installed, "privoxy"),
            ] {
                if !present {
                    return Err(Error::Config(format!(
                        "{name} is not installed; install it with your package manager, then re-run `ratriyx setup --install --yes`"
                    )));
                }
            }
        }
    }
    let forwarding =
        privoxy::read_effective_for(Path::new(&cfg.privoxy_config), &cfg.desired_rule());
    let tor_running = service::tor_state()
        .map(|s| s.instance_running)
        .unwrap_or(false);
    let privoxy_running = service::unit_active(service::PRIVOXY).unwrap_or(false);
    let plan = install_plan(&facts, &forwarding, tor_running, privoxy_running);
    if plan.is_empty() {
        if let Some(reason) = diagnostics::verify_route_with_timeout(cfg, 10) {
            return Err(Error::Verification(format!(
                "Tor and Privoxy appear installed, but routing is unverified: {reason}"
            )));
        }
        say!("setup: Tor and Privoxy are healthy; route verified (IsTor true)");
        return Ok(0);
    }
    if !yes {
        return Err(Error::Approval(format!(
            "managed setup would:\n  {}\nre-run with --install --yes to approve",
            plan.join("\n  ")
        )));
    }
    managed::stamp(&dir)?;
    let path = PathBuf::from(&cfg.privoxy_config);
    let mut edited = false;
    let mut started: Vec<&str> = Vec::new();
    if matches!(forwarding, privoxy::FwState::Absent) {
        say!(
            "{}",
            privoxy::configure_file_for(&path, &cfg.desired_rule(), false, true)?
        );
        let backup = privoxy::latest_backup(&path)
            .ok_or_else(|| Error::Io(format!("no ratriyx backup found for {}", path.display())))?;
        let current = fs::read(&path).map_err(fsutil::io_err)?;
        managed::record_file(&dir, &path, &sha256_hex(&current), &backup)?;
        edited = true;
    } else if let privoxy::FwState::Conflicting(rules) = &forwarding {
        return Err(Error::Verification(format!(
            "Privoxy rules at lines {} route destinations directly; review them by hand, then re-run",
            rules
                .iter()
                .map(|r| r.line.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    for (running, unit) in [
        (tor_running, service::TOR_INSTANCE),
        (privoxy_running, service::PRIVOXY),
    ] {
        if !running {
            if let Err(e) = service::control("start", unit, true) {
                rollback(&path, edited, &started);
                return Err(e);
            }
            say!("started {unit}");
            if let Err(e) = managed::record_service(&dir, unit) {
                rollback(&path, edited, &started);
                return Err(e);
            }
            started.push(unit);
        }
    }
    match diagnostics::verify_route_with_timeout(cfg, 10) {
        None => {
            say!("setup: managed services started and the route verified (IsTor true)");
            Ok(0)
        }
        Some(reason) => {
            rollback(&path, edited, &started);
            Err(Error::Verification(format!(
                "route did not verify ({reason}); managed changes were rolled back"
            )))
        }
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
    use crate::infrastructure::winmanaged as wm;
    let Some(base) = wm::managed_base() else {
        return Err(Error::Config(
            "cannot find LOCALAPPDATA for managed setup".into(),
        ));
    };
    let listeners = service::listening().unwrap_or_default();
    for port in [9050u16, 9051, 8118] {
        if !wm::port_free(&listeners, port) {
            return Err(Error::Verification(format!(
                "port {port} is already occupied; managed setup refuses to take it over"
            )));
        }
    }
    let mut plan = Vec::new();
    if !facts.tor_installed {
        plan.push(format!(
            "download Tor {} and verify its checksum",
            wm::TOR_BUNDLE_VERSION
        ));
        plan.push("write owned torrc and start managed Tor".to_string());
    }
    if !facts.privoxy_installed {
        plan.push("install Privoxy through WinGet".to_string());
        plan.push("write owned Privoxy config and start managed Privoxy".to_string());
    }
    if !yes {
        return Err(Error::Approval(format!(
            "managed setup would:\n  {}\nre-run with --install --yes to approve",
            plan.join("\n  ")
        )));
    }
    let tor_dir = base.join("tor");
    let data_dir = tor_dir.join("Data");
    let torrc = tor_dir.join("torrc");
    let conf = base.join("privoxy.conf");
    let tor_pid = wm::pid_path(dir, "tor");
    let tor_stderr_log = dir.join("setup-tor-stderr.log");
    // Tor writes notices to stderr; the launcher persists both startup
    // diagnostics and bootstrap updates in this Ratriyx-owned log.
    let tor_notices = tor_stderr_log.clone();
    let tor_dir_preexisting = tor_dir.exists();
    let conf_preexisting = conf.exists();
    let privoxy_pid = wm::pid_path(dir, "privoxy");
    let rollback_created = |started: &[PathBuf]| {
        for pid in started.iter().rev() {
            let _ = wm::stop_tracked(pid);
        }
        eprintln!("  [ROLLBACK] Stopping only processes started by this setup");
        if !tor_dir_preexisting {
            let _ = fs::remove_dir_all(&tor_dir);
        }
        if !conf_preexisting {
            let _ = fs::remove_file(&conf);
        }
        eprintln!(
            "  Tor startup stderr was preserved: {}",
            tor_stderr_log.display()
        );
    };
    let mut started: Vec<PathBuf> = Vec::new();
    let total = (if !facts.tor_installed { 3 } else { 0 })
        + (if !facts.privoxy_installed { 2 } else { 0 })
        + 1;
    let mut step = 0usize;
    crate::interface::terminal::install_header();
    macro_rules! stage {
        ($message:expr) => {{
            step += 1;
            crate::interface::terminal::install_stage(step, total, $message);
        }};
    }
    // Tor first: Privoxy needs it.
    if !facts.tor_installed {
        stage!("Downloading and verifying Tor...");
        let bundle = winpkg::execute(
            &winpkg::Action::Fetch {
                url: wm::TOR_BUNDLE_URL.into(),
                sha256: wm::TOR_BUNDLE_SHA256.into(),
            },
            &base,
        )?;
        crate::interface::terminal::install_done("Tor bundle SHA-256 verified");
        if let Err(e) = (|| -> Result<()> {
            stage!("Extracting Tor and writing configuration...");
            wm::extract_bundle(&bundle.path, &tor_dir)?;
            fs::create_dir_all(&data_dir).map_err(fsutil::io_err)?;
            fs::write(&torrc, wm::torrc_text(&data_dir, 9050, 9051)).map_err(fsutil::io_err)?;
            let exe = tor_dir.join("Tor").join("tor.exe");
            if !exe.exists() {
                return Err(Error::Verification(format!(
                    "bundle has no {}",
                    exe.display()
                )));
            }
            let torrc_arg = torrc.to_string_lossy().to_string();
            eprintln!("  Validating Tor configuration...");
            let check = std::process::Command::new(&exe)
                .args(["-f", torrc_arg.as_str(), "--verify-config"])
                .output()
                .map_err(|err| Error::Io(format!("cannot validate Tor config: {err}")))?;
            if !check.status.success() {
                return Err(Error::Verification(format!(
                    "Tor rejected its configuration ({}): {} {}",
                    check.status,
                    String::from_utf8_lossy(&check.stdout).trim(),
                    String::from_utf8_lossy(&check.stderr).trim()
                )));
            }
            crate::interface::terminal::install_done("Tor archive extracted; torrc validated");
            stage!("Starting Tor on SOCKS5 port 9050...");
            let mut child = wm::spawn_tracked_logged(
                &exe,
                &["-f", torrc_arg.as_str()],
                &tor_pid,
                &tor_stderr_log,
            )?;
            started.push(tor_pid.clone());
            wm::wait_for_socks_with_child(
                "127.0.0.1:9050",
                60,
                &mut child,
                &tor_stderr_log,
                &tor_notices,
            )?;
            crate::interface::terminal::install_done("Tor SOCKS5 ready on 127.0.0.1:9050");
            Ok(())
        })() {
            rollback_created(&started);
            return Err(e);
        }
    }
    if !facts.privoxy_installed {
        if let Err(e) = (|| -> Result<()> {
            stage!("Installing Privoxy through WinGet...");
            winpkg::execute(
                &winpkg::Action::WingetInstall {
                    package: wm::PRIVOXY_WINGET_ID.into(),
                },
                &base,
            )?;
            crate::interface::terminal::install_done("Privoxy installed through WinGet");
            let path_var = env::var_os("PATH").unwrap_or_default();
            let exe = wm::find_privoxy_exe(&path_var).ok_or_else(|| {
                Error::Verification(
                    "Privoxy was installed but privoxy.exe could not be located; check the WinGet installation path before proceeding".into(),
                )
            })?;
            fs::write(&conf, wm::privoxy_conf_text(8118, "127.0.0.1:9050"))
                .map_err(fsutil::io_err)?;
            let conf_arg = conf.to_string_lossy().to_string();
            stage!("Starting Privoxy on HTTP port 8118...");
            wm::spawn_tracked(&exe, &[conf_arg.as_str()], &privoxy_pid)?;
            started.push(privoxy_pid.clone());
            wait_for_listener(8118, 30)?;
            crate::interface::terminal::install_done("Privoxy HTTP proxy ready on 127.0.0.1:8118");
            Ok(())
        })() {
            rollback_created(&started);
            return Err(e);
        }
    }
    let mcfg = Config {
        privoxy_config: conf.to_string_lossy().to_string(),
        tor_cookie_path: data_dir
            .join("control_auth_cookie")
            .to_string_lossy()
            .to_string(),
        ..cfg.clone()
    };
    stage!("Verifying actual Tor routing (IsTor)...");
    match diagnostics::verify_route_with_timeout(&mcfg, 30) {
        None => {
            // An incomplete install must not leave a successful ownership
            // record behind: commit managed metadata only after IsTor=true.
            let record_result = (|| -> Result<()> {
                managed::stamp(dir)?;
                if !facts.tor_installed {
                    managed::record_dependency(
                        dir,
                        "tor",
                        "official-download:tor-expert-bundle",
                        wm::TOR_BUNDLE_VERSION,
                        wm::TOR_BUNDLE_SHA256,
                    )?;
                    managed::record_file(dir, &torrc, "", &PathBuf::new())?;
                }
                if !facts.privoxy_installed {
                    managed::record_dependency(
                        dir,
                        "privoxy",
                        "winget:Privoxy.Privoxy",
                        "unknown",
                        "package-manager",
                    )?;
                    managed::record_file(dir, &conf, "", &PathBuf::new())?;
                }
                Ok(())
            })();
            if let Err(err) = record_result {
                rollback_created(&started);
                return Err(err);
            }
            crate::interface::terminal::install_success(total);
            say!("setup: managed Tor and Privoxy installed, route verified (IsTor true)");
            Ok(0)
        }
        Some(reason) => {
            rollback_created(&started);
            Err(Error::Verification(format!(
                "route did not verify ({reason}); managed changes were rolled back"
            )))
        }
    }
}

/// Polls the listener table until `port` appears or the deadline passes.
#[cfg(windows)]
fn wait_for_listener(port: u16, deadline_secs: u64) -> Result<()> {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    loop {
        let listeners = service::listening().unwrap_or_default();
        if !crate::infrastructure::winmanaged::port_free(&listeners, port) {
            return Ok(());
        }
        if start.elapsed() >= Duration::from_secs(deadline_secs) {
            return Err(Error::Verification(format!(
                "nothing listening on port {port} after {deadline_secs}s; refusing to continue"
            )));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn rollback(path: &Path, edited: bool, started: &[&str]) {
    if edited {
        let _ = rollback_managed(path);
    }
    for unit in started.iter().rev() {
        let _ = service::control("stop", unit, true);
    }
}

fn rollback_managed(path: &Path) -> Result<()> {
    let backup = privoxy::latest_backup(path).ok_or_else(|| {
        Error::Io(format!(
            "no ratriyx backup found for rollback of {}",
            path.display()
        ))
    })?;
    privoxy::restore_file(path, &backup, true)?;
    let _ = service::control("restart", service::PRIVOXY, true);
    Ok(())
}

/// Pure plan behind `setup_install`: facts in, human-readable steps out.
fn install_plan(
    facts: &setup::SetupFacts,
    forwarding: &privoxy::FwState,
    tor_running: bool,
    privoxy_running: bool,
) -> Vec<String> {
    let _ = facts;
    let mut plan = Vec::new();
    if matches!(forwarding, privoxy::FwState::Absent) {
        plan.push("append the Privoxy forwarding rule with a backup".to_string());
    }
    if !tor_running {
        plan.push(format!("start {}", service::TOR_INSTANCE));
    }
    if !privoxy_running {
        plan.push(format!("start {}", service::PRIVOXY));
    }
    plan
}

pub fn recover(cfg: &Config, target: Mode, apply: bool, yes: bool) -> Result<i32> {
    let stale: Vec<String> = PROXY_VARS
        .iter()
        .filter(|name| env::var_os(name).is_some())
        .map(|name| name.to_string())
        .collect();
    let facts = recovery::Facts {
        stale_proxy_vars: stale,
        tor_running: service::tor_state()
            .map(|s| s.instance_running)
            .unwrap_or(false),
        privoxy_running: service::unit_active(service::PRIVOXY).unwrap_or(false),
        forwarding_present: matches!(
            privoxy::read_effective_for(Path::new(&cfg.privoxy_config), &cfg.desired_rule()),
            privoxy::FwState::Present
        ),
        istor: match target {
            Mode::Tor => Some(diagnostics::route_verified_with_timeout(cfg, 5)),
            Mode::Direct => None,
        },
    };
    let plan = recovery::plan(target, &facts);
    show!("{}", recovery::render(&plan));
    if apply {
        for line in recovery::apply(&plan, yes)? {
            say!("{line}");
        }
    } else {
        eprintln!(
            "ratriyx: dry run; nothing changed. Use --apply --yes to start approved services"
        );
    }
    Ok(0)
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
    use crate::interface::setup::SetupFacts;

    fn facts() -> SetupFacts {
        SetupFacts {
            platform: "test".into(),
            support: "test".into(),
            systemd: false,
            tor_installed: true,
            privoxy_installed: true,
            curl_installed: true,
            package_manager: None,
            forwarding: String::new(),
            tor_state: String::new(),
        }
    }

    #[test]
    fn healthy_setup_needs_no_steps() {
        let f = facts();
        assert!(install_plan(&f, &privoxy::FwState::Present, true, true).is_empty());
    }

    #[test]
    fn missing_rule_and_stopped_services_each_get_a_step() {
        let f = facts();
        let plan = install_plan(&f, &privoxy::FwState::Absent, false, false);
        assert_eq!(plan.len(), 3);
        assert!(plan[0].contains("forwarding"));
        assert!(install_plan(&f, &privoxy::FwState::Present, true, false).len() == 1);
    }

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
