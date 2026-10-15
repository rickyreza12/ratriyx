use crate::application::recovery;
use crate::domain::error::{Error, Result};
use crate::domain::route::{Mode, PROXY_VARS};
use crate::infrastructure::config::{self, Config};
use crate::infrastructure::fsutil;
use crate::infrastructure::privoxy;
use crate::infrastructure::service;
use crate::infrastructure::shell;
use crate::interface::cli::ShellKind;
use crate::interface::diagnostics;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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
    let mut owned: Vec<PathBuf> = Vec::new();
    if let Some(path) = config::config_file().filter(|p| p.exists()) {
        owned.push(path);
    }
    if let Some(dir) = shell::state_dir() {
        for kind in [
            ShellKind::Bash,
            ShellKind::Zsh,
            ShellKind::Fish,
            ShellKind::PowerShell,
        ] {
            // Default session plus any per-session snapshots.
            let snapshot = shell::snapshot_path(&dir, kind);
            if snapshot.exists() {
                owned.push(snapshot);
            }
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("env-snapshot-") {
                    owned.push(entry.path());
                }
            }
        }
        owned.sort();
        owned.dedup();
        let rotate = dir.join("rotate.last");
        if rotate.exists() {
            owned.push(rotate);
        }
    }
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
