//! Honest local privacy assessment. Tor changes routing for participating
//! clients, not the identity disclosed by accounts or application payloads.
use crate::domain::error::{Error, Result};
use crate::infrastructure::config::Config;
use crate::infrastructure::embedded_proxy::EmbeddedProxy;
use crate::infrastructure::network::{self, Route};
use crate::interface::diagnostics::{verification_failure, VERIFY_URL};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    name: &'static str,
    status: &'static str,
    message: String,
}

fn findings(verified: bool, inherited_proxy: bool) -> Vec<Finding> {
    vec![
        Finding {
            name: "tor.route",
            status: if verified { "PASS" } else { "FAIL" },
            message: if verified { "This HTTPS probe arrived through Tor (IsTor=true)." }
                else { "Tor routing could not be verified; do not assume privacy." }.into(),
        },
        Finding {
            name: "app.isolation",
            status: "WARN",
            message: "No OS guard protects all descendants, raw TCP, UDP, IPv6 or direct DNS; --strict still refuses.".into(),
        },
        Finding {
            name: "account.identity",
            status: "UNKNOWN",
            message: "Logins, account tokens, cookies, request content, browser fingerprints and timing can link sessions even with a Tor exit.".into(),
        },
        Finding {
            name: "shell.proxy",
            status: if inherited_proxy { "WARN" } else { "INFO" },
            message: if inherited_proxy { "This shell has ambient proxy environment variables; check their scope and owner." }
                else { "This shell has no ambient proxy variables; application-specific settings still require verification." }.into(),
        },
        Finding {
            name: "provider.quota",
            status: "INFO",
            message: "Provider HTTP 429/free usage limits are separate from transport. Circuit changes do not reset accounts or quotas.".into(),
        },
    ]
}

fn escape_json(value: &str) -> String {
    let mut s = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            c if c.is_control() => s.push_str(&format!("\\u{:04x}", c as u32)),
            other => s.push(other),
        }
    }
    s.push('"');
    s
}

pub fn check(cfg: &Config, json: bool) -> Result<i32> {
    let socks: SocketAddr = cfg
        .tor_socks_addr()
        .parse()
        .map_err(|_| Error::Config("invalid Tor SOCKS5 socket address".into()))?;
    let proxy = EmbeddedProxy::start(socks)?;
    let request = network::fetch(
        &Route::Proxy(format!("http://{}", proxy.address())),
        VERIFY_URL,
        20,
    );
    let failure = verification_failure(&request.outcome);
    let inherited = crate::domain::route::PROXY_VARS
        .iter()
        .any(|key| std::env::var_os(key).is_some());
    let items = findings(failure.is_none(), inherited);
    if json {
        let parts: Vec<String> = items
            .iter()
            .map(|i| {
                format!(
                    "{{\"id\":{},\"status\":{},\"message\":{}}}",
                    escape_json(i.name),
                    escape_json(i.status),
                    escape_json(&i.message)
                )
            })
            .collect();
        say!("[{}]", parts.join(","));
    } else {
        for item in items {
            say!("[{}] {}: {}", item.status, item.name, item.message);
        }
        if let Some(reason) = &failure {
            eprintln!("ratriyx: Tor verification failed: {reason}");
        }
    }
    Ok(if failure.is_some() { 4 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verification_does_not_claim_anonymity() {
        let report = findings(true, false);
        assert_eq!(report[0].status, "PASS");
        assert_eq!(report[1].status, "WARN");
        assert_eq!(report[2].status, "UNKNOWN");
        assert!(report[2].message.contains("cookies"));
    }
    #[test]
    fn unverified_probe_is_a_failure_and_json_is_escaped() {
        assert_eq!(findings(false, true)[0].status, "FAIL");
        assert_eq!(escape_json("a\"\\\n"), "\"a\\\"\\\\\\n\"");
    }
}
