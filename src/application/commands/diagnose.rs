use crate::domain::error::Result;
use crate::domain::route::Mode;
use crate::infrastructure::config::Config;
use crate::infrastructure::shell;
use crate::infrastructure::tor_control;
use crate::interface::diagnostics;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn doctor(cfg: &Config, json: bool, mode: Mode, app: Option<&str>) -> Result<i32> {
    let checks = diagnostics::run_doctor(cfg, mode, app);
    let out = if json {
        format!("{}\n", diagnostics::render_json(&checks))
    } else if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        crate::interface::terminal::doctor(&checks)
    } else {
        diagnostics::render_text(&checks)
    };
    show!("{out}");
    Ok(diagnostics::exit_code(&checks))
}

pub fn ip(cfg: &Config) -> Result<i32> {
    let lines = diagnostics::run_ip(cfg);
    for line in &lines {
        say!("{line}");
    }
    Ok(if diagnostics::ip_verified(&lines) {
        0
    } else {
        1
    })
}

pub fn status(cfg: &Config) -> Result<i32> {
    let lines = diagnostics::run_status(cfg);
    for line in &lines {
        say!("{line}");
    }
    Ok(if diagnostics::status_verified(&lines) {
        0
    } else {
        1
    })
}

pub fn rotate(cfg: &Config, yes: bool) -> Result<i32> {
    let state = shell::require_state_dir()?.join("rotate.last");
    say!("{}", tor_control::rotate(cfg, &state, unix_now(), yes)?);
    match diagnostics::verify_route(cfg) {
        None => {
            say!("post-NEWNYM check: IsTor true; the route still goes through Tor");
            Ok(0)
        }
        Some(reason) => {
            say!("post-NEWNYM check: not verified ({reason})");
            Ok(1)
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
