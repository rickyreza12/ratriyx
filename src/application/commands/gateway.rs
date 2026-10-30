//! Opt-in alternate egress via an independently operated local SOCKS5 gateway.
//! This does not create a VPN, evade provider limits, or enforce OS-wide isolation.
use crate::domain::error::{Error, Result};
use crate::domain::route::{self, Mode};
use crate::infrastructure::config::Config;
use crate::infrastructure::embedded_proxy::EmbeddedProxy;
use crate::infrastructure::network::{self, Route};
use crate::infrastructure::runner;
use crate::interface::diagnostics;
use std::net::{IpAddr, SocketAddr};

fn socket(endpoint: &str) -> Result<SocketAddr> {
    let address: SocketAddr = endpoint.parse().map_err(|_| {
        Error::Usage(
            "--socks must be a numeric loopback SOCKS5 address, e.g. 127.0.0.1:1080".into(),
        )
    })?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(Error::Usage(
            "--socks must target a locally controlled loopback listener".into(),
        ));
    }
    Ok(address)
}

fn checked_public_ip(route: &Route, name: &str) -> Result<IpAddr> {
    let result = network::fetch(route, diagnostics::DIRECT_URL, 15);
    let response = result.outcome.map_err(|error| {
        Error::Verification(format!(
            "{name} IP probe failed: {}",
            diagnostics::net_error_text(&error)
        ))
    })?;
    if response.status != 200 {
        return Err(Error::Verification(format!(
            "{name} IP probe returned HTTP {}; refusing unverified route",
            response.status
        )));
    }
    response.body.trim().parse().map_err(|_| {
        Error::Verification(format!(
            "{name} IP probe did not return a valid public IP; refusing unverified route"
        ))
    })
}

fn changed_ip(direct: IpAddr, routed: IpAddr, excluded: Option<IpAddr>) -> Result<()> {
    if direct == routed {
        return Err(Error::Verification(format!(
            "gateway egress {routed} equals direct public IP; refusing to launch"
        )));
    }
    if excluded == Some(routed) {
        return Err(Error::Verification(format!(
            "gateway egress {routed} equals excluded IP; refusing to launch"
        )));
    }
    Ok(())
}

fn verify(
    socks: &str,
    different_from: Option<IpAddr>,
    trace_connections: bool,
) -> Result<(EmbeddedProxy, String)> {
    let endpoint = socket(socks)?;
    network::socks5_greeting(socks)
        .map_err(|error| Error::Verification(format!("SOCKS5 gateway not ready: {error}")))?;
    let proxy = if trace_connections {
        EmbeddedProxy::start_traced(endpoint)?
    } else {
        EmbeddedProxy::start(endpoint)?
    };
    let url = format!("http://{}", proxy.address());
    // Verify the precise embedded proxy that will be passed to the child,
    // not the system proxy or an unrelated SOCKS5 listener.
    let direct = checked_public_ip(&Route::Direct, "direct")?;
    let routed = checked_public_ip(&Route::Proxy(url.clone()), "gateway")?;
    eprintln!("ratriyx: direct public IP: {direct}");
    eprintln!("ratriyx: gateway public IP: {routed}");
    changed_ip(direct, routed, different_from)?;
    eprintln!("ratriyx: gateway egress differs from direct and excluded IP");
    Ok((proxy, url))
}

pub fn check(socks: &str, different_from: Option<IpAddr>) -> Result<i32> {
    let (_proxy, _url) = verify(socks, different_from, false)?;
    say!("gateway check: verified public egress different from direct");
    say!("scope: proxy-aware applications only; not OS-wide network isolation");
    Ok(0)
}

pub fn run(
    socks: &str,
    different_from: Option<IpAddr>,
    trace_connections: bool,
    opencode: bool,
    program: &str,
    args: &[String],
) -> Result<i32> {
    let (proxy, url) = verify(socks, different_from, trace_connections)?;
    if opencode {
        for note in route::opencode_boundary_notes() {
            eprintln!("ratriyx: {note}");
        }
    }
    let env = route::mode_env(Mode::Tor, &url);
    proxy.begin_application_trace();
    let result = runner::run_child(program, args, &env);
    proxy.end_application_trace();
    result
}

#[cfg(windows)]
fn existing_tor_exit(cfg: &Config) -> Result<IpAddr> {
    let address = cfg.tor_socks_addr();
    network::socks5_greeting(&address).map_err(|_| {
        Error::Verification(
            "the existing Tor SOCKS5 listener is unavailable; start the normal Tor route first"
                .into(),
        )
    })?;
    let socks = socket(&address)?;
    let proxy = EmbeddedProxy::start(socks)?;
    let mut config = cfg.clone();
    config.proxy_host = proxy.address().ip().to_string();
    config.proxy_port = proxy.address().port();
    let ip = diagnostics::verify_tor_exit_ip(&config, 20)
        .map_err(|e| Error::Verification(format!("existing Tor verification failed: {e}")))?
        .ok_or_else(|| Error::Verification("existing Tor did not report an exit IP".into()))?;
    ip.parse()
        .map_err(|_| Error::Verification("existing Tor exit IP is invalid".into()))
}

/// Run a second, temporary Tor daemon with a new data directory and its own
/// SOCKS listener. It excludes the current Tor exit while selecting circuits.
/// This changes the verified probe egress, not the provider account identity.
#[cfg(windows)]
fn local_tor_route(
    cfg: &Config,
    different_from: Option<IpAddr>,
    trace_connections: bool,
) -> Result<(
    crate::infrastructure::isolated_tor::IsolatedTor,
    EmbeddedProxy,
    String,
)> {
    use crate::infrastructure::isolated_tor::IsolatedTor;

    let direct = checked_public_ip(&Route::Direct, "direct")?;
    let existing = existing_tor_exit(cfg)?;
    eprintln!("ratriyx: direct public IP: {direct}");
    eprintln!("ratriyx: existing Tor exit IP: {existing}");
    let mut exclusions = vec![existing];
    if let Some(previous) = different_from {
        if !exclusions.contains(&previous) {
            exclusions.push(previous);
        }
    }
    let isolated = IsolatedTor::start(&exclusions)?;
    let proxy = if trace_connections {
        EmbeddedProxy::start_traced(isolated.socks())?
    } else {
        EmbeddedProxy::start(isolated.socks())?
    };
    let mut config = cfg.clone();
    config.proxy_host = proxy.address().ip().to_string();
    config.proxy_port = proxy.address().port();
    let mut exit_ip = None;
    for attempt in 1..=4 {
        match diagnostics::verify_tor_exit_ip(&config, 15) {
            Ok(Some(value)) => {
                exit_ip = Some(value.parse::<IpAddr>().map_err(|_| {
                    Error::Verification("alternate Tor exit returned an invalid IP".into())
                })?);
                break;
            }
            Ok(None) => return Err(Error::Verification("alternate Tor exit IP missing".into())),
            Err(reason) if attempt < 4 && transient_bootstrap_failure(&reason) => {
                eprintln!("ratriyx: new Tor circuit warming up: {reason} ({attempt}/4)");
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            Err(reason) => {
                return Err(Error::Verification(format!(
                    "alternate Tor IsTor check failed: {reason}"
                )));
            }
        }
    }
    let exit = exit_ip.ok_or_else(|| Error::Verification("alternate Tor exit not ready".into()))?;
    eprintln!("ratriyx: alternate Tor exit IP: {exit} (IsTor=true)");
    changed_ip(direct, exit, Some(existing))?;
    if different_from == Some(exit) {
        return Err(Error::Verification(format!(
            "alternate Tor exit {exit} equals excluded IP; refusing"
        )));
    }
    eprintln!("ratriyx: verified distinct Tor exit; only proxy-aware child connections are scoped");
    Ok((isolated, proxy, config.proxy_url()))
}

#[cfg(windows)]
fn transient_bootstrap_failure(reason: &str) -> bool {
    reason.contains("connection refused")
        || reason.contains("timed out")
        || reason.contains("empty reply")
}

pub fn tor_check(cfg: &Config, different_from: Option<IpAddr>) -> Result<i32> {
    #[cfg(windows)]
    {
        let (_tor, _proxy, _) = local_tor_route(cfg, different_from, false)?;
        say!("second local Tor route: distinct exit verified, temporary process stopped at exit");
        Ok(0)
    }
    #[cfg(not(windows))]
    {
        let _ = (cfg, different_from);
        Err(Error::Unsupported(
            "gateway tor currently supports managed Tor on native Windows only".into(),
        ))
    }
}

pub fn tor_run(
    cfg: &Config,
    different_from: Option<IpAddr>,
    trace_connections: bool,
    opencode: bool,
    program: &str,
    args: &[String],
) -> Result<i32> {
    #[cfg(windows)]
    {
        let (_tor, proxy, url) = local_tor_route(cfg, different_from, trace_connections)?;
        if opencode {
            for note in route::opencode_boundary_notes() {
                eprintln!("ratriyx: {note}");
            }
        }
        // Tor and proxy stay alive until child exits, then are stopped.
        let env = route::mode_env(Mode::Tor, &url);
        proxy.begin_application_trace();
        let result = runner::run_child(program, args, &env);
        proxy.end_application_trace();
        result
    }
    #[cfg(not(windows))]
    {
        let _ = (
            cfg,
            different_from,
            trace_connections,
            opencode,
            program,
            args,
        );
        Err(Error::Unsupported(
            "gateway tor currently supports managed Tor on native Windows only".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn gateway_requires_a_loopback_socks5_listener() {
        assert!(socket("127.0.0.1:1080").is_ok());
        assert!(socket("[::1]:1080").is_ok());
        for bad in [
            "example.org:1080",
            "192.0.2.1:1080",
            "127.0.0.1:0",
            "invalid",
        ] {
            assert!(socket(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn gateway_never_accepts_unchanged_or_excluded_ip() {
        assert!(changed_ip(ip(1), ip(1), None).is_err());
        assert!(changed_ip(ip(1), ip(2), Some(ip(2))).is_err());
        assert!(changed_ip(ip(1), ip(2), Some(ip(3))).is_ok());
        assert!(changed_ip(ip(1), ip(2), None).is_ok());
    }

    #[test]
    fn missing_gateway_refuses_before_starting_child() {
        let error = run(
            "127.0.0.1:1",
            None,
            false,
            false,
            "definitely-missing-child",
            &[],
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("SOCKS5 gateway not ready"));
    }
}
