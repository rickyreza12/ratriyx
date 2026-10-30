use crate::domain::error::Result;
use crate::domain::route::Mode;
use crate::infrastructure::config::Config;
use crate::infrastructure::embedded_proxy::EmbeddedProxy;
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

pub fn ip(cfg: &Config, privoxy: bool) -> Result<i32> {
    // Keep this listener alive until the proxied Tor request completes.
    // Legacy Privoxy remains opt-in for comparing the two backends.
    let mut probe_cfg = cfg.clone();
    let _proxy = if privoxy {
        None
    } else {
        let socks = cfg.tor_socks_addr().parse().map_err(|_| {
            crate::domain::error::Error::Config("invalid Tor SOCKS5 socket address".into())
        })?;
        let proxy = EmbeddedProxy::start(socks)?;
        probe_cfg.proxy_host = proxy.address().ip().to_string();
        probe_cfg.proxy_port = proxy.address().port();
        Some(proxy)
    };
    let lines = diagnostics::run_ip(&probe_cfg);
    say!(
        "proxy backend: {}",
        if privoxy {
            "privoxy (legacy)"
        } else {
            "embedded Rust -> Tor SOCKS5"
        }
    );
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
    // Check the same embedded backend used by default run/ip; do not depend
    // on a separately installed Privoxy service for circuit verification.
    let mut probe_cfg = cfg.clone();
    let socks = cfg
        .tor_socks_addr()
        .parse()
        .map_err(|_| crate::domain::error::Error::Config("invalid Tor SOCKS5 address".into()))?;
    let _proxy = EmbeddedProxy::start(socks)?;
    probe_cfg.proxy_host = _proxy.address().ip().to_string();
    probe_cfg.proxy_port = _proxy.address().port();
    match diagnostics::verify_route(&probe_cfg) {
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

pub fn rotate_status(cfg: &Config) -> Result<i32> {
    let state = shell::require_state_dir()?.join("rotate.last");
    let last = std::fs::read_to_string(&state)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
    let remain = tor_control::cooldown_remaining(last, unix_now());
    say!(
        "Tor control configured: {}",
        if cfg.tor_control_enabled { "yes" } else { "no" }
    );
    say!("Local NEWNYM cooldown remaining: {remain}s");
    say!("Tor may rate-limit NEWNYM independently; active TCP connections retain their existing circuits.");
    say!("NEWNYM is for circuit separation, not to circumvent an account's HTTP 429 or free-usage quota.");
    Ok(0)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
