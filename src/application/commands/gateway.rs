//! Opt-in alternate egress via an independently operated local SOCKS5 gateway.
//! This does not create a VPN, evade provider limits, or enforce OS-wide isolation.
use crate::domain::error::{Error, Result};
use crate::domain::route::{self, Mode};
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

fn verify(socks: &str, different_from: Option<IpAddr>) -> Result<(EmbeddedProxy, String)> {
    let endpoint = socket(socks)?;
    network::socks5_greeting(socks)
        .map_err(|error| Error::Verification(format!("SOCKS5 gateway not ready: {error}")))?;
    let proxy = EmbeddedProxy::start(endpoint)?;
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
    let (_proxy, _url) = verify(socks, different_from)?;
    say!("gateway check: verified public egress different from direct");
    say!("scope: proxy-aware applications only; not OS-wide network isolation");
    Ok(0)
}

pub fn run(
    socks: &str,
    different_from: Option<IpAddr>,
    opencode: bool,
    program: &str,
    args: &[String],
) -> Result<i32> {
    let (_proxy, url) = verify(socks, different_from)?;
    if opencode {
        for note in route::opencode_boundary_notes() {
            eprintln!("ratriyx: {note}");
        }
    }
    let env = route::mode_env(Mode::Tor, &url);
    runner::run_child(program, args, &env)
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
        let error = run("127.0.0.1:1", None, false, "definitely-missing-child", &[]).unwrap_err();
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("SOCKS5 gateway not ready"));
    }
}
