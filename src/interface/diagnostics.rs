use crate::domain::route::{Mode, PROXY_VARS};
use crate::infrastructure::config::Config;
use crate::infrastructure::network::{self, NetError, Response, Route};
use crate::infrastructure::opencode;
use crate::infrastructure::privoxy::{self, FwState};
use crate::infrastructure::redact;
use crate::infrastructure::service::{self, TorState};
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::Path;

pub const DIRECT_URL: &str = "https://api.ipify.org";
pub const VERIFY_URL: &str = "https://check.torproject.org/api/ip";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
    NotTested,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::NotTested => "NOT_TESTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: String,
    pub category: &'static str,
    pub status: Status,
    pub evidence: String,
    pub elapsed_ms: Option<u128>,
    pub next_step: Option<String>,
}

fn check(
    id: &str,
    category: &'static str,
    status: Status,
    evidence: &str,
    next: Option<&str>,
) -> Check {
    Check {
        id: id.to_string(),
        category,
        status,
        evidence: evidence.to_string(),
        elapsed_ms: None,
        next_step: next.map(str::to_string),
    }
}

impl Check {
    fn timed(mut self, elapsed_ms: u128) -> Check {
        self.elapsed_ms = Some(elapsed_ms);
        self
    }
}

/// In Tor mode a missing route is a failure. In direct mode the same absence is simply not tested.
fn tor_failure(mode: Mode) -> Status {
    match mode {
        Mode::Tor => Status::Fail,
        Mode::Direct => Status::NotTested,
    }
}

pub fn net_error_text(err: &NetError) -> String {
    match err {
        NetError::Refused => "connection refused; the endpoint is not listening".into(),
        NetError::Timeout => "timed out".into(),
        NetError::Dns => "DNS resolution failed".into(),
        NetError::Tls => "TLS certificate verification failed; verification is not disabled".into(),
        NetError::EmptyReply => "empty reply; Tor may still be building circuits".into(),
        NetError::ToolMissing => "curl is not installed or not on PATH".into(),
        NetError::Other(code) => format!("curl failed with exit code {code}"),
    }
}

pub fn eval_env(vars: &[(String, String)], mode: Mode) -> Vec<Check> {
    if vars.is_empty() {
        return vec![check(
            "env.proxy",
            "environment",
            Status::Pass,
            "no proxy variables set in this process",
            None,
        )];
    }
    let listed = vars
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(", ");
    match mode {
        Mode::Direct => vec![check(
            "env.proxy",
            "environment",
            Status::Warn,
            &format!("proxy variables set in this process: {listed}"),
            Some("clear them with `eval \"$(ratriyx off --shell bash)\"` or start children with `ratriyx run --mode direct --`"),
        )],
        Mode::Tor => vec![check(
            "env.proxy",
            "environment",
            Status::Pass,
            &format!("proxy variables set in this process: {listed}"),
            None,
        )],
    }
}

pub fn eval_tor_unit(state: Option<&TorState>, mode: Mode) -> Check {
    match state {
        None => check(
            "tor.instance",
            "tor",
            Status::NotTested,
            "service manager unavailable",
            None,
        ),
        Some(s) if s.instance_running => check(
            "tor.instance",
            "tor",
            Status::Pass,
            &format!("{} running; master tor {}", s.unit, s.master_state),
            None,
        ),
        Some(s) => check(
            "tor.instance",
            "tor",
            tor_failure(mode),
            &format!(
                "{} not running (sub state {}); master tor {}",
                s.unit, s.instance_sub, s.master_state
            ),
            Some("start it with `ratriyx service start tor --yes`, after reviewing the change"),
        ),
    }
}

pub fn eval_listener(
    port: u16,
    listeners: Option<&[service::Listener]>,
    mode: Mode,
    label: &'static str,
) -> Check {
    let id = format!("listener.{port}");
    let Some(listeners) = listeners else {
        return check(
            &id,
            "listener",
            Status::NotTested,
            "listener data unavailable",
            None,
        );
    };
    let Some(l) = service::find_listener(listeners, port) else {
        return check(
            &id,
            "listener",
            tor_failure(mode),
            &format!("nothing listening on port {port}"),
            Some("check the service that should own this port"),
        );
    };
    if l.is_loopback() {
        let proc = l
            .process
            .as_deref()
            .map(|p| format!(" (process: {p})"))
            .unwrap_or_default();
        check(
            &id,
            "listener",
            Status::Pass,
            &format!("{label} listening on loopback {}:{port}{proc}", l.addr),
            None,
        )
    } else {
        check(
            &id,
            "listener",
            tor_failure(mode),
            &format!(
                "{label} on {addr}:{port} is not loopback-only{}; loopback safety is not claimed",
                if service::is_wildcard_addr(&l.addr) {
                    " (wildcard bind)"
                } else {
                    ""
                },
                addr = l.addr
            ),
            Some("bind the service to 127.0.0.1 or ::1 before using Tor mode"),
        )
    }
}

pub fn eval_platform(platform: &crate::infrastructure::platform::Platform) -> Check {
    let level = platform.support_level();
    let status = if level.starts_with("supported") {
        Status::Pass
    } else if level.starts_with("unsupported") {
        Status::Fail
    } else {
        Status::Warn
    };
    check(
        "platform.support",
        "platform",
        status,
        &format!(
            "{}; backend {:?}; {level}",
            platform.describe(),
            platform.service_backend()
        ),
        None,
    )
}

pub fn eval_bootstrap(percent: Option<u8>, mode: Mode) -> Check {
    match percent {
        Some(100) => check(
            "tor.bootstrap",
            "tor",
            Status::Pass,
            "Tor bootstrapped 100%",
            None,
        ),
        Some(p) => check(
            "tor.bootstrap",
            "tor",
            tor_failure(mode),
            &format!("Tor bootstrapped {p}%; circuits may not be ready"),
            Some("wait for Bootstrapped 100%, then re-run"),
        ),
        None => check(
            "tor.bootstrap",
            "tor",
            Status::NotTested,
            "bootstrap log unavailable",
            None,
        ),
    }
}

/// Words an HTTP status by its class. The status is never retried and never called a proxy fault.
pub fn status_meaning(status: u16) -> &'static str {
    match network::classify_status(status) {
        network::HttpClass::Success => "success",
        network::HttpClass::Authentication => {
            "the endpoint refused the request; credentials are not shown"
        }
        network::HttpClass::RateLimited => {
            "the endpoint rate-limited the request; this is a provider limit, not a proxy fault"
        }
        network::HttpClass::NotFound => "not found",
        network::HttpClass::Server => "server error at the endpoint",
        network::HttpClass::Other => "unexpected status",
    }
}

/// Functional check of the Tor SOCKS port. A bound port is not enough; it must answer SOCKS5.
pub fn eval_socks(result: &std::result::Result<(), String>, addr: &str, mode: Mode) -> Check {
    match result {
        Ok(()) => check(
            "tor.socks",
            "tor",
            Status::Pass,
            &format!("SOCKS5 greeting answered at {addr}"),
            None,
        ),
        Err(msg) => check(
            "tor.socks",
            "tor",
            tor_failure(mode),
            &format!("SOCKS5 check at {addr} failed: {msg}"),
            Some("check tor@default and its SocksPort"),
        ),
    }
}

pub fn eval_forwarding(state: &FwState, mode: Mode) -> Check {
    let id = "privoxy.forwarding";
    match state {
        FwState::Present => check(
            id,
            "forwarding",
            Status::Pass,
            "forward-socks5t rule present",
            None,
        ),
        FwState::Absent => check(
            id,
            "forwarding",
            tor_failure(mode),
            "forward-socks5t rule missing",
            Some("ratriyx configure --dry-run, then ratriyx configure --yes"),
        ),
        FwState::Conflicting(rules) => {
            let lines = rules
                .iter()
                .map(|r| r.line.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            check(
                id,
                "forwarding",
                tor_failure(mode),
                &format!("rules at lines {lines} route destinations directly or catch all traffic"),
                Some("review those lines by hand; ratriyx will not edit them"),
            )
        }
        FwState::Unreadable(msg) => check(
            id,
            "forwarding",
            tor_failure(mode),
            &format!("Privoxy config unreadable ({msg})"),
            Some("check the path and permissions"),
        ),
    }
}

pub fn eval_direct(outcome: &std::result::Result<Response, NetError>, mode: Mode) -> Check {
    match outcome {
        Ok(r) if r.status == 200 => check(
            "direct.https",
            "direct",
            Status::Pass,
            "direct HTTPS reachable (HTTP 200); DNS via the local resolver; no address recorded",
            None,
        ),
        Ok(r) => check(
            "direct.https",
            "direct",
            Status::Warn,
            &format!("direct check returned HTTP {}", r.status),
            None,
        ),
        Err(e) => {
            let status = match mode {
                Mode::Direct => Status::Fail,
                Mode::Tor => Status::Warn,
            };
            check(
                "direct.https",
                "direct",
                status,
                &format!("direct request failed: {}", net_error_text(e)),
                Some("check the general network connection"),
            )
        }
    }
}

fn normalized(body: &str) -> String {
    body.chars().filter(|c| !c.is_whitespace()).collect()
}

pub fn eval_istor(
    outcome: &std::result::Result<Response, NetError>,
    endpoint: &str,
    mode: Mode,
) -> Check {
    let id = "tor.istor";
    match outcome {
        Ok(r) if r.status == 200 => {
            let body = normalized(&r.body);
            if body.contains("\"IsTor\":true") {
                check(
                    id,
                    "tor",
                    Status::Pass,
                    &format!("IsTor true through {endpoint}; DNS resolved through Tor"),
                    None,
                )
            } else if body.contains("\"IsTor\":false") {
                check(
                    id,
                    "tor",
                    tor_failure(mode),
                    "IsTor false: the request did not arrive through Tor",
                    Some("inspect Privoxy forwarding with `ratriyx doctor`"),
                )
            } else {
                check(
                    id,
                    "tor",
                    tor_failure(mode),
                    "unexpected body from the verification endpoint",
                    None,
                )
            }
        }
        Ok(r) if r.status == 407 => check(
            id,
            "tor",
            tor_failure(mode),
            "proxy requires authentication (HTTP 407); credentials are not shown",
            Some("check whether Privoxy has an authentication rule"),
        ),
        Ok(r) if r.status == 429 => check(
            id,
            "tor",
            Status::Warn,
            &format!(
                "verification endpoint rate-limited (HTTP 429): {}",
                status_meaning(429)
            ),
            Some("wait before retrying; the route itself was not shown to fail"),
        ),
        Ok(r) => check(
            id,
            "tor",
            tor_failure(mode),
            &format!(
                "verification endpoint returned HTTP {} ({})",
                r.status,
                status_meaning(r.status)
            ),
            None,
        ),
        Err(NetError::ToolMissing) => {
            check(id, "tor", Status::NotTested, "curl is not installed", None)
        }
        Err(e) => check(
            id,
            "tor",
            tor_failure(mode),
            &format!(
                "verification through {endpoint} failed: {}",
                net_error_text(e)
            ),
            Some("check that Privoxy is listening and Tor has finished bootstrapping"),
        ),
    }
}

pub fn eval_opencode(res: &opencode::Resolution) -> Check {
    let id = "opencode.resolution";
    let Some(path) = &res.path else {
        return check(
            id,
            "opencode",
            Status::NotTested,
            "opencode not found on PATH",
            None,
        );
    };
    let version = res.version.as_deref().unwrap_or("unknown version");
    let standalone = match res.standalone {
        Some(true) => "lists --standalone",
        Some(false) => "does not list --standalone",
        None => "help unavailable",
    };
    let server = match res.server {
        Some(true) => "; local server running (restart it to apply a new route)",
        Some(false) => "; no local server running",
        None => "; server state unknown (no status probe)",
    };
    let evidence = format!(
        "{} ({}), {version}, {standalone}{server}",
        path.display(),
        res.kind.text(),
    );
    match res.kind {
        opencode::Kind::InteropLauncher => {
            check(
                id,
                "opencode",
                Status::Warn,
                &format!("{evidence}; its environment is set by WSLENV, which ratriyx cannot verify"),
                Some("run it through `ratriyx run --opencode --allow-unverified` only if you accept an unverified route"),
            )
        }
        _ => check(id, "opencode", Status::Pass, &evidence, None),
    }
}

pub fn provider_check() -> Check {
    check(
        "provider.probe",
        "provider",
        Status::NotTested,
        "provider probe is opt-in and not configured in this build; no paid request was made",
        None,
    )
}

/// None when the proxied request returned IsTor true. Otherwise the reason it did not.
pub fn verification_failure(outcome: &std::result::Result<Response, NetError>) -> Option<String> {
    match outcome {
        Ok(r) if r.status == 200 && normalized(&r.body).contains("\"IsTor\":true") => None,
        Ok(r) if r.status == 200 => Some("IsTor was not true".into()),
        Ok(r) => Some(format!("verification endpoint returned HTTP {}", r.status)),
        Err(e) => Some(net_error_text(e)),
    }
}

pub fn verify_route(cfg: &Config) -> Option<String> {
    verify_route_with_timeout(cfg, 30)
}

pub fn verify_route_with_timeout(cfg: &Config, timeout_secs: u64) -> Option<String> {
    let probe = network::fetch(&Route::Proxy(cfg.proxy_url()), VERIFY_URL, timeout_secs);
    verification_failure(&probe.outcome)
}

pub fn route_verified_with_timeout(cfg: &Config, timeout_secs: u64) -> bool {
    verify_route_with_timeout(cfg, timeout_secs).is_none()
}

fn masked_proxy_vars() -> Vec<(String, String)> {
    PROXY_VARS
        .iter()
        .filter_map(|name| {
            env::var(name)
                .ok()
                .map(|v| (name.to_string(), redact::mask_value(name, &v)))
        })
        .collect()
}

pub fn run_doctor(cfg: &Config, mode: Mode, app: Option<&str>) -> Vec<Check> {
    let mut checks = vec![eval_platform(&crate::infrastructure::platform::detect())];
    checks.extend(eval_env(&masked_proxy_vars(), mode));
    checks.push(eval_tor_unit(service::tor_state().as_ref(), mode));
    checks.push(eval_bootstrap(service::tor_bootstrap_percent(), mode));
    let listening = service::listening();
    let listeners = listening.as_deref();
    checks.push(eval_listener(cfg.tor_socks_port, listeners, mode, "tor"));
    let socks_addr = cfg.tor_socks_addr();
    checks.push(eval_socks(
        &network::socks5_greeting(&socks_addr),
        &socks_addr,
        mode,
    ));
    checks.push(eval_listener(cfg.proxy_port, listeners, mode, "privoxy"));
    let desired = cfg.desired_rule();
    checks.push(eval_forwarding(
        &privoxy::read_effective_for(Path::new(&cfg.privoxy_config), &desired),
        mode,
    ));

    let direct = network::fetch(&Route::Direct, DIRECT_URL, 15);
    checks.push(eval_direct(&direct.outcome, mode).timed(direct.elapsed_ms));
    let proxied = network::fetch(&Route::Proxy(cfg.proxy_url()), VERIFY_URL, 30);
    checks.push(eval_istor(&proxied.outcome, &cfg.proxy_url(), mode).timed(proxied.elapsed_ms));

    match app {
        Some("opencode") => {
            let path_var: OsString = env::var_os("PATH").unwrap_or_default();
            checks.push(eval_opencode(&opencode::resolve(&path_var)));
        }
        Some(other) => checks.push(check(
            "app.unknown",
            "app",
            Status::NotTested,
            &format!("no diagnostics for app {other}"),
            None,
        )),
        None => {}
    }
    checks.push(provider_check());
    checks
}

/// Exit 1 when any check failed. Otherwise exit 0.
pub fn exit_code(checks: &[Check]) -> i32 {
    if checks.iter().any(|c| c.status == Status::Fail) {
        1
    } else {
        0
    }
}

fn summary(checks: &[Check]) -> String {
    let count = |s: Status| checks.iter().filter(|c| c.status == s).count();
    format!(
        "summary: {} pass, {} warn, {} fail, {} not tested",
        count(Status::Pass),
        count(Status::Warn),
        count(Status::Fail),
        count(Status::NotTested)
    )
}

pub fn render_text(checks: &[Check]) -> String {
    let mut out = String::new();
    for c in checks {
        let _ = writeln!(
            out,
            "[{}] {} ({}): {}",
            c.status.label(),
            c.id,
            c.category,
            redact::redact_text(&c.evidence)
        );
        if let Some(step) = &c.next_step {
            let _ = writeln!(out, "       next: {}", redact::redact_text(step));
        }
    }
    let _ = writeln!(out, "{}", summary(checks));
    out
}

fn json_str(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn render_json(checks: &[Check]) -> String {
    let items: Vec<String> = checks
        .iter()
        .map(|c| {
            let elapsed = c.elapsed_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".into());
            let next = match &c.next_step {
                Some(step) => json_str(&redact::redact_text(step)),
                None => "null".into(),
            };
            format!(
                "{{\"id\":{},\"category\":{},\"status\":{},\"evidence\":{},\"elapsed_ms\":{},\"next_step\":{}}}",
                json_str(&c.id),
                json_str(c.category),
                json_str(c.status.label()),
                json_str(&redact::redact_text(&c.evidence)),
                elapsed,
                next
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let mut rest = body.find(&marker).map(|i| &body[i + marker.len()..])?;
    rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_string())
}

/// `ip` reports direct and proxied results separately. An IP difference is not treated as proof of Tor.
pub fn run_ip(cfg: &Config) -> Vec<String> {
    let direct = network::fetch(&Route::Direct, DIRECT_URL, 15);
    let proxied = network::fetch(&Route::Proxy(cfg.proxy_url()), VERIFY_URL, 30);
    let mut lines = Vec::new();
    match &direct.outcome {
        Ok(r) if r.status == 200 => lines.push(format!(
            "direct:  {} ({} ms)",
            r.body.trim(),
            direct.elapsed_ms
        )),
        Ok(r) => lines.push(format!("direct:  HTTP {}", r.status)),
        Err(e) => lines.push(format!("direct:  failed: {}", net_error_text(e))),
    }
    match &proxied.outcome {
        Ok(r) if r.status == 200 => {
            let exit = extract_json_string(&r.body, "IP").unwrap_or_else(|| "unknown".into());
            lines.push(format!("proxied: exit {exit} ({} ms)", proxied.elapsed_ms));
            let istor = if normalized(&r.body).contains("\"IsTor\":true") {
                "true"
            } else if normalized(&r.body).contains("\"IsTor\":false") {
                "false"
            } else {
                "unknown"
            };
            lines.push(format!("tor:     IsTor={istor}"));
        }
        Ok(r) => lines.push(format!("proxied: HTTP {}", r.status)),
        Err(e) => {
            lines.push(format!("proxied: failed: {}", net_error_text(e)));
            lines.push("tor:     IsTor=unknown".into());
        }
    }
    lines.push(
        "note: an IP difference does not prove Tor routing; IsTor is the verification signal"
            .into(),
    );
    lines
}

pub fn run_status(cfg: &Config) -> Vec<String> {
    let mut lines = vec![
        format!("proxy endpoint:   {}", cfg.proxy_url()),
        format!(
            "tor socks:        {}:{}",
            cfg.tor_socks_host, cfg.tor_socks_port
        ),
        format!(
            "tor control:      {}",
            if cfg.tor_control_enabled {
                "enabled (cookie auth)"
            } else {
                "disabled"
            }
        ),
        format!("privoxy config:   {}", cfg.privoxy_config),
    ];
    lines.push(match service::tor_state() {
        Some(s) if s.instance_running => {
            format!("{}:      running (master {})", s.unit, s.master_state)
        }
        Some(s) => format!("{}:      not running (master {})", s.unit, s.master_state),
        None => "tor:      unknown (service manager unavailable)".into(),
    });
    lines.push(match service::unit_active(service::PRIVOXY) {
        Some(true) => "privoxy:          active".into(),
        Some(false) => "privoxy:          not active".into(),
        None => "privoxy:          unknown".into(),
    });
    lines.push(format!(
        "privoxy forwarding: {:?}",
        privoxy::read_effective_for(Path::new(&cfg.privoxy_config), &cfg.desired_rule())
    ));
    let vars = masked_proxy_vars();
    if vars.is_empty() {
        lines.push("process env:      no proxy variables (this ratriyx process only)".into());
    } else {
        for (name, value) in vars {
            lines.push(format!("process env:      {name}={value}"));
        }
    }
    lines.push(format!(
        "route:            {}",
        if route_verified_with_timeout(cfg, 5) {
            "verified (IsTor true)"
        } else {
            "not verified"
        }
    ));
    lines.push(
        "scope:            per process here; the current shell is not changed by this command"
            .into(),
    );
    lines
}

/// True when `run_ip` output shows a verified Tor route.
pub fn ip_verified(lines: &[String]) -> bool {
    lines.iter().any(|l| l.trim() == "tor:     IsTor=true")
}

/// True when `run_status` output shows a verified route.
pub fn status_verified(lines: &[String]) -> bool {
    lines
        .iter()
        .any(|l| l.contains("route:") && l.contains("verified (IsTor true)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(status: u16, body: &str) -> std::result::Result<Response, NetError> {
        Ok(Response {
            status,
            body: body.into(),
        })
    }

    #[test]
    fn istor_true_passes_and_istor_false_fails_in_tor_mode() {
        assert_eq!(
            eval_istor(&ok(200, "{\"IsTor\":true}"), "x", Mode::Tor).status,
            Status::Pass
        );
        assert_eq!(
            eval_istor(&ok(200, "{\"IsTor\":false}"), "x", Mode::Tor).status,
            Status::Fail
        );
    }

    #[test]
    fn istor_is_not_tested_in_direct_mode_when_route_is_absent() {
        let refused = Err(NetError::Refused);
        assert_eq!(
            eval_istor(&refused, "127.0.0.1:8118", Mode::Direct).status,
            Status::NotTested
        );
        assert_eq!(
            eval_istor(&refused, "127.0.0.1:8118", Mode::Tor).status,
            Status::Fail
        );
    }

    #[test]
    fn proxy_auth_is_classified_without_disclosing_credentials() {
        let c = eval_istor(&ok(407, ""), "x", Mode::Tor);
        assert!(c.evidence.contains("407"));
        assert_eq!(c.status, Status::Fail);
    }

    #[test]
    fn stopped_tor_is_acceptable_in_direct_mode_and_failure_in_tor_mode() {
        let stopped = TorState {
            instance_running: false,
            instance_sub: "dead".into(),
            master_state: "active/exited".into(),
            unit: "tor@default".into(),
        };
        assert_eq!(
            eval_tor_unit(Some(&stopped), Mode::Direct).status,
            Status::NotTested
        );
        assert_eq!(
            eval_tor_unit(Some(&stopped), Mode::Tor).status,
            Status::Fail
        );
    }

    #[test]
    fn master_unit_active_exited_is_not_readiness() {
        let stopped = TorState {
            instance_running: false,
            instance_sub: "dead".into(),
            master_state: "active/exited".into(),
            unit: "tor@default".into(),
        };
        let c = eval_tor_unit(Some(&stopped), Mode::Tor);
        assert_ne!(c.status, Status::Pass);
    }

    #[test]
    fn direct_failure_fails_only_in_direct_mode() {
        let err = Err(NetError::Timeout);
        assert_eq!(eval_direct(&err, Mode::Direct).status, Status::Fail);
        assert_eq!(eval_direct(&err, Mode::Tor).status, Status::Warn);
    }

    #[test]
    fn stale_proxy_variables_warn_in_direct_mode_with_masked_values() {
        let vars = vec![(
            "HTTP_PROXY".to_string(),
            "http://***@127.0.0.1:8118".to_string(),
        )];
        let checks = eval_env(&vars, Mode::Direct);
        assert_eq!(checks[0].status, Status::Warn);
        assert!(!checks[0].evidence.contains("secret"));
    }

    #[test]
    fn rate_limit_is_not_a_proxy_failure() {
        let check = eval_istor(&ok(429, "rate limit"), "x", Mode::Tor);
        assert_eq!(check.status, Status::Warn);
        assert!(check.evidence.contains("rate-limited"));
        assert!(!check.evidence.contains("refused"));
        assert_eq!(provider_check().status, Status::NotTested);
    }

    #[test]
    fn json_output_is_escaped_and_redacted() {
        let checks = vec![check(
            "a",
            "c",
            Status::Pass,
            "quote \" and http://u:p@h",
            None,
        )];
        let json = render_json(&checks);
        assert!(json.contains("quote \\\" and http://***@h"));
        assert!(json.starts_with('[') && json.ends_with(']'));
    }

    #[test]
    fn exit_code_is_one_only_when_something_failed() {
        let pass = vec![check("a", "c", Status::Pass, "", None)];
        let fail = vec![check("a", "c", Status::Fail, "", None)];
        assert_eq!(exit_code(&pass), 0);
        assert_eq!(exit_code(&fail), 1);
    }

    #[test]
    fn socks_check_is_functional_not_just_a_bound_port() {
        assert_eq!(
            eval_socks(&Ok(()), "127.0.0.1:9050", Mode::Tor).status,
            Status::Pass
        );
        let err = Err("listener did not answer as SOCKS5".to_string());
        assert_eq!(
            eval_socks(&err, "127.0.0.1:9050", Mode::Tor).status,
            Status::Fail
        );
        assert_eq!(
            eval_socks(&err, "127.0.0.1:9050", Mode::Direct).status,
            Status::NotTested
        );
    }

    #[test]
    fn rate_limit_and_auth_statuses_are_named_by_class() {
        assert!(status_meaning(429).contains("provider limit"));
        assert!(status_meaning(401).contains("refused"));
        assert!(status_meaning(500).contains("server error"));
    }

    #[test]
    fn verification_failure_names_the_reason() {
        assert_eq!(verification_failure(&ok(200, "{\"IsTor\":true}")), None);
        assert_eq!(
            verification_failure(&ok(200, "{\"IsTor\":false}")),
            Some("IsTor was not true".into())
        );
        assert!(verification_failure(&Err(NetError::Refused))
            .unwrap()
            .contains("connection refused"));
    }

    #[test]
    fn ip_body_field_is_extracted() {
        assert_eq!(
            extract_json_string("{\"IsTor\":true,\"IP\":\"203.0.113.9\"}", "IP").as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            extract_json_string("{ \"IP\" : \"203.0.113.9\" }", "IP").as_deref(),
            Some("203.0.113.9")
        );
    }

    #[test]
    fn loopback_listener_passes_and_wildcard_fails_in_tor_mode() {
        let loopback = vec![service::Listener {
            addr: "127.0.0.1".into(),
            port: 8118,
            process: Some("privoxy".into()),
        }];
        let c = eval_listener(8118, Some(&loopback), Mode::Tor, "privoxy");
        assert_eq!(c.status, Status::Pass);
        assert!(c.evidence.contains("privoxy"));
        let wild = vec![service::Listener {
            addr: "0.0.0.0".into(),
            port: 8118,
            process: None,
        }];
        assert_eq!(
            eval_listener(8118, Some(&wild), Mode::Tor, "privoxy").status,
            Status::Fail
        );
        assert_eq!(
            eval_listener(8118, Some(&[]), Mode::Tor, "privoxy").status,
            Status::Fail
        );
        assert_eq!(
            eval_listener(8118, None, Mode::Tor, "privoxy").status,
            Status::NotTested
        );
    }

    #[test]
    fn ip_and_status_lines_report_verification_truthfully() {
        assert!(ip_verified(&["tor:     IsTor=true".to_string()]));
        assert!(!ip_verified(&["tor:     IsTor=false".to_string()]));
        assert!(status_verified(&[
            "route:            verified (IsTor true)".to_string()
        ]));
        assert!(!status_verified(&[
            "route:            not verified".to_string()
        ]));
    }
}
