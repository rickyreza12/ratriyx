use super::path_var;
use crate::domain::error::{Error, Result};
use crate::domain::route::{self, Mode, Verify};
use crate::infrastructure::config::Config;
use crate::infrastructure::embedded_proxy::EmbeddedProxy;
use crate::infrastructure::network::{self, Route};
use crate::infrastructure::opencode;
use crate::infrastructure::runner;
use crate::infrastructure::shell;
use crate::infrastructure::strict_guard;
use crate::interface::cli::ShellKind;
use crate::interface::diagnostics;

pub struct RunOptions<'a> {
    pub mode: Mode,
    pub verify: Verify,
    pub strict: bool,
    pub embedded_proxy: bool,
    pub trace_connections: bool,
    pub opencode: bool,
    pub program: &'a str,
    pub args: &'a [String],
}

pub fn run(cfg: &Config, options: RunOptions<'_>) -> Result<i32> {
    let RunOptions {
        mode,
        verify,
        strict,
        embedded_proxy,
        trace_connections,
        opencode,
        program,
        args,
    } = options;
    // Acquire the enforcement lease BEFORE any child process is launched.
    // Environment proxy variables cannot substitute for OS isolation.
    // Keep the lease alive until the launched application exits.
    let _guard = if strict {
        Some(strict_guard::acquire(program)?)
    } else {
        None
    };
    // On Windows an explicitly installed, Ratriyx-owned Tor can be restarted
    // without downloads. This does not alter system proxy or network settings.
    #[cfg(windows)]
    if mode == Mode::Tor && embedded_proxy {
        crate::infrastructure::winmanaged::ensure_managed_tor(cfg)?;
    }
    // Own an ephemeral loopback proxy for the entire child lifetime. Never
    // launch until this proxy's real Tor route has passed IsTor verification.
    let mut embedded_cfg = cfg.clone();
    let _embedded = if embedded_proxy {
        let socks = cfg
            .tor_socks_addr()
            .parse()
            .map_err(|_| Error::Config("invalid Tor SOCKS5 socket address".into()))?;
        let server = if trace_connections {
            EmbeddedProxy::start_traced(socks)?
        } else {
            EmbeddedProxy::start(socks)?
        };
        embedded_cfg.proxy_host = server.address().ip().to_string();
        embedded_cfg.proxy_port = server.address().port();
        Some(server)
    } else {
        None
    };
    let cfg = &embedded_cfg;
    let path = path_var();
    let interop = opencode::program_is_interop(program, &path);
    if opencode && args.iter().any(|a| a == "--standalone") {
        let resolution = opencode::resolve(&path);
        if resolution.standalone != Some(true) {
            return Err(Error::Usage(
                "this opencode does not list --standalone; remove the flag or check the installed version".into(),
            ));
        }
    }
    let probe_needed = mode == Mode::Tor && !(interop && verify == Verify::Require);
    let probe = if probe_needed {
        Some(diagnostics::verify_tor_exit_ip(cfg, 30))
    } else {
        None
    };
    let failure = probe
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .cloned();
    let verified = probe.as_ref().is_some_and(|result| result.is_ok());
    match route::decide(mode, verify, verified, interop) {
        route::Decision::Refuse(msg) => Err(Error::Verification(match failure {
            Some(reason) => format!("{msg}; the proxied check said: {reason}"),
            None => msg,
        })),
        route::Decision::Launch(label) => {
            let mode_name = match mode {
                Mode::Direct => "direct",
                Mode::Tor => "tor",
            };
            eprintln!("ratriyx: route {} ({mode_name} mode)", label.text());
            if mode == Mode::Tor {
                if let Some(Some(ip)) = probe.and_then(|result| result.ok()) {
                    eprintln!("ratriyx: verified Tor exit IP: {ip}");
                }
            } else {
                let direct = network::fetch(&Route::Direct, diagnostics::DIRECT_URL, 10);
                match direct.outcome {
                    Ok(response) if response.status == 200 => {
                        let ip = response.body.trim();
                        if ip.parse::<std::net::IpAddr>().is_ok() {
                            eprintln!("ratriyx: direct public IP: {ip}");
                        } else {
                            eprintln!(
                                "ratriyx: direct public IP unavailable (unexpected response)"
                            );
                        }
                    }
                    Ok(response) => {
                        eprintln!("ratriyx: direct IP check returned HTTP {}", response.status)
                    }
                    Err(err) => eprintln!(
                        "ratriyx: direct IP check failed: {}",
                        diagnostics::net_error_text(&err)
                    ),
                }
            }
            if opencode {
                for note in route::opencode_boundary_notes() {
                    eprintln!("ratriyx: {note}");
                }
            }
            let plan = route::mode_env(mode, &cfg.proxy_url());
            if let Some(proxy) = &_embedded {
                proxy.begin_application_trace();
            }
            let result = runner::run_child(program, args, &plan);
            if let Some(proxy) = &_embedded {
                proxy.end_application_trace();
            }
            result
        }
    }
}

pub fn env(cfg: &Config, shell_kind: ShellKind, mode: Mode, session: &str) -> Result<i32> {
    if mode == Mode::Tor {
        return Err(Error::Usage(
            "a shell environment cannot own an ephemeral embedded proxy; use `ratriyx run --mode tor -- <program>` instead".into(),
        ));
    }
    let dir = shell::require_state_dir()?;
    shell::ensure_snapshot_for(&dir, shell_kind, session)?;
    let plan = route::mode_env(mode, &cfg.proxy_url());
    show!("{}", shell::render_plan(shell_kind, &plan));
    eprintln!(
        "ratriyx: review the lines above, then eval or source them in your shell. Undo with `ratriyx off --session {session}`. Processes already running keep their environment."
    );
    Ok(0)
}

pub fn off(shell_kind: ShellKind, session: &str) -> Result<i32> {
    let dir = shell::require_state_dir()?;
    let snapshot = shell::snapshot_path_for(&dir, shell_kind, session);
    if snapshot.exists() {
        say!("{}", shell::source_line(shell_kind, &snapshot));
    } else {
        show!(
            "{}",
            shell::render_plan(shell_kind, &route::mode_env(Mode::Direct, ""))
        );
        eprintln!("ratriyx: no snapshot found; unsetting proxy variables instead");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_shell_environment_refuses_before_creating_state() {
        let result = env(&Config::default(), ShellKind::PowerShell, Mode::Tor, "test");
        let error = result.expect_err("an ephemeral proxy cannot survive a shell snippet");
        assert!(error.to_string().contains("ratriyx run"));
        assert_eq!(error.exit_code(), 2);
    }
}
