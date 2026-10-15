use crate::domain::error::{Error, Result};
use crate::infrastructure::config::Config;
use crate::infrastructure::fsutil;
use crate::infrastructure::privoxy;
use crate::infrastructure::service;
use crate::interface::diagnostics;
use std::fs;
use std::path::{Path, PathBuf};

pub fn configure(
    cfg: &Config,
    dry_run: bool,
    yes: bool,
    restart: bool,
    file: Option<&str>,
) -> Result<i32> {
    let path = target_path(cfg, file);
    let desired = cfg.desired_rule();
    let report = privoxy::configure_file_for(&path, &desired, dry_run || !yes, yes)?;
    say!("{report}");
    if restart {
        if dry_run || !yes {
            return Err(Error::Approval(
                "restarting Privoxy changes a running service; re-run with --yes --restart".into(),
            ));
        }
        say!("{}", configure_restart(cfg, &path)?);
    }
    Ok(0)
}

pub fn restore(cfg: &Config, yes: bool, file: Option<&str>) -> Result<i32> {
    let path = target_path(cfg, file);
    let backup = privoxy::latest_backup(&path)
        .ok_or_else(|| Error::Io(format!("no ratriyx backup found for {}", path.display())))?;
    say!("{}", privoxy::restore_file(&path, &backup, yes)?);
    Ok(0)
}

fn target_path(cfg: &Config, file: Option<&str>) -> PathBuf {
    file.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&cfg.privoxy_config))
}

/// Validated restart after a config edit: validate the file, restart Privoxy,
/// verify forwarding and the route, and roll back on failure.
fn configure_restart(cfg: &Config, path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).map_err(fsutil::io_err)?;
    privoxy::validate_config_text(&text, &cfg.desired_rule())?;
    say!("{}", service::control("restart", service::PRIVOXY, true)?);
    let desired = cfg.desired_rule();
    match privoxy::read_effective_for(path, &desired) {
        privoxy::FwState::Present => {}
        other => {
            rollback_after_restart(path)?;
            return Err(Error::Verification(format!(
                "Privoxy restarted but forwarding is {other:?}; the backup was restored"
            )));
        }
    }
    match diagnostics::verify_route(cfg) {
        None => Ok("privoxy restarted and the route verified (IsTor true)".into()),
        Some(reason) => {
            rollback_after_restart(path)?;
            Err(Error::Verification(format!(
                "Privoxy restarted but the route did not verify ({reason}); the backup was restored"
            )))
        }
    }
}

fn rollback_after_restart(path: &Path) -> Result<()> {
    let Some(backup) = privoxy::latest_backup(path) else {
        return Err(Error::Io("no ratriyx backup found for rollback".into()));
    };
    privoxy::restore_file(path, &backup, true)?;
    let _ = service::control("restart", service::PRIVOXY, true);
    Ok(())
}
