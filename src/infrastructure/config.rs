use crate::domain::error::{Error, Result};
use crate::infrastructure::fsutil::{atomic_write, io_err};
use crate::infrastructure::platform;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub privoxy_config: String,
    pub tor_socks_host: String,
    pub tor_socks_port: u16,
    pub tor_control_enabled: bool,
    pub tor_control_host: String,
    pub tor_control_port: u16,
    pub tor_cookie_path: String,
    pub tor_control_socket: String,
    pub default_target: String,
    pub runner_mode: String,
    pub require_tor: bool,
    pub localhost_only: bool,
    pub verify_tls: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            proxy_host: "127.0.0.1".into(),
            proxy_port: 8118,
            privoxy_config: platform::default_privoxy_path(),
            tor_socks_host: "127.0.0.1".into(),
            tor_socks_port: 9050,
            tor_control_enabled: false,
            tor_control_host: String::new(),
            tor_control_port: 9051,
            tor_cookie_path: platform::default_cookie_path(),
            tor_control_socket: String::new(),
            default_target: "opencode".into(),
            runner_mode: "per_process".into(),
            require_tor: true,
            localhost_only: true,
            verify_tls: true,
        }
    }
}

impl Config {
    /// Strict TOML subset: `[section]` headers, `key = value`, `#` comments.
    /// Unknown keys are errors so typos cannot silently disable a safety setting.
    pub fn parse(text: &str) -> Result<Config> {
        let mut cfg = Config::default();
        let mut section = String::new();
        let mut seen = std::collections::HashSet::new();
        for (index, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let at = |msg: String| Error::Config(format!("line {}: {msg}", index + 1));
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.trim().to_string();
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| at("expected key = value".into()))?;
            let full_key = format!("{}.{}", section, key.trim());
            if !seen.insert(full_key.clone()) {
                return Err(at(format!("duplicate key {full_key}")));
            }
            set(&mut cfg, &full_key, value.trim()).map_err(at)?;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        for (label, host) in [
            ("proxy.host", &self.proxy_host),
            ("tor.socks_host", &self.tor_socks_host),
        ] {
            let ip: IpAddr = host
                .parse()
                .map_err(|_| Error::Config(format!("{label} must be a loopback IP address")))?;
            if !ip.is_loopback() {
                return Err(Error::Config(format!(
                    "{label} must be loopback; non-loopback addresses are refused"
                )));
            }
        }
        if !self.tor_control_host.trim().is_empty() {
            let ip: IpAddr = self.tor_control_host.parse().map_err(|_| {
                Error::Config("tor.control_host must be a loopback IP address".into())
            })?;
            if !ip.is_loopback() {
                return Err(Error::Config(
                    "tor.control_host must be loopback; non-loopback addresses are refused".into(),
                ));
            }
        }
        if !self.localhost_only {
            return Err(Error::Config("security.localhost_only must be true".into()));
        }
        if !self.verify_tls {
            return Err(Error::Config("security.verify_tls must be true".into()));
        }
        if !self.require_tor {
            return Err(Error::Config(
                "runner.require_tor must be true; fail-closed is the only supported mode".into(),
            ));
        }
        if self.runner_mode != "per_process" {
            return Err(Error::Config("runner.mode must be \"per_process\"".into()));
        }
        if self.default_target.trim().is_empty() {
            return Err(Error::Config(
                "runner.default_target must not be empty".into(),
            ));
        }
        for (label, port) in [
            ("proxy.port", self.proxy_port),
            ("tor.socks_port", self.tor_socks_port),
            ("tor.control_port", self.tor_control_port),
        ] {
            if port == 0 {
                return Err(Error::Config(format!(
                    "{label} must be a port number above 0"
                )));
            }
        }
        if self.privoxy_config.trim().is_empty() {
            return Err(Error::Config(
                "privoxy.config_path must not be empty".into(),
            ));
        }
        if self.tor_control_enabled && self.tor_cookie_path.trim().is_empty() {
            return Err(Error::Config(
                "tor.cookie_path is required when tor.control_enabled is true".into(),
            ));
        }
        if !self.tor_control_socket.is_empty() && !is_absolute_path(&self.tor_control_socket) {
            return Err(Error::Config(
                "tor.control_socket must be an absolute path".into(),
            ));
        }
        Ok(())
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}", host_port(&self.proxy_host, self.proxy_port))
    }

    fn socks_target(&self) -> String {
        host_port(&self.tor_socks_host, self.tor_socks_port)
    }

    /// Forwarding rule built from the configured SOCKS endpoint, so custom
    /// loopback ports do not silently get the default 127.0.0.1:9050 rule.
    pub fn desired_rule(&self) -> String {
        format!("forward-socks5t / {} .", self.socks_target())
    }

    pub fn tor_socks_addr(&self) -> String {
        host_port(&self.tor_socks_host, self.tor_socks_port)
    }

    pub fn tor_control_addr(&self) -> String {
        let host = if self.tor_control_host.trim().is_empty() {
            &self.tor_socks_host
        } else {
            &self.tor_control_host
        };
        if host.contains(':') {
            format!("[{host}]:{}", self.tor_control_port)
        } else {
            format!("{host}:{}", self.tor_control_port)
        }
    }
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn is_absolute_path(value: &str) -> bool {
    if value.starts_with('/') {
        return true;
    }
    // Windows drive (`C:\...`, `C:/...`) or UNC (`\\server\...`).
    let bytes = value.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    value.starts_with(r"\\")
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

fn set(cfg: &mut Config, key: &str, value: &str) -> std::result::Result<(), String> {
    match key {
        "proxy.host" => cfg.proxy_host = quoted(value)?,
        "proxy.port" => cfg.proxy_port = port(value)?,
        "proxy.config_path" => cfg.privoxy_config = quoted(value)?,
        "privoxy.config_path" => cfg.privoxy_config = quoted(value)?,
        "tor.socks_host" => cfg.tor_socks_host = quoted(value)?,
        "tor.socks_port" => cfg.tor_socks_port = port(value)?,
        "tor.control_enabled" => cfg.tor_control_enabled = boolean(value)?,
        "tor.control_host" => cfg.tor_control_host = quoted(value)?,
        "tor.control_port" => cfg.tor_control_port = port(value)?,
        "tor.cookie_path" => cfg.tor_cookie_path = quoted(value)?,
        "tor.control_socket" => cfg.tor_control_socket = quoted(value)?,
        "runner.default_target" => cfg.default_target = quoted(value)?,
        "runner.mode" => cfg.runner_mode = quoted(value)?,
        "runner.require_tor" => cfg.require_tor = boolean(value)?,
        "security.localhost_only" => cfg.localhost_only = boolean(value)?,
        "security.verify_tls" => cfg.verify_tls = boolean(value)?,
        other => return Err(format!("unknown key {other}")),
    }
    Ok(())
}

fn quoted(value: &str) -> std::result::Result<String, String> {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .map(str::to_string)
        .ok_or_else(|| format!("expected a quoted string, got {value}"))
}

fn port(value: &str) -> std::result::Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("expected a port number, got {value}"))
}

fn boolean(value: &str) -> std::result::Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("expected true or false, got {other}")),
    }
}

/// `$XDG_CONFIG_HOME/<app>`, `%LOCALAPPDATA%/<app>` on Windows, or `$HOME/.config/<app>`.
pub fn config_dir(app: &str) -> Option<PathBuf> {
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join(app));
    }
    if cfg!(windows) {
        if let Some(local) = env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(local).join(app));
        }
    }
    env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(|home| PathBuf::from(home).join(".config").join(app))
}

pub fn config_file() -> Option<PathBuf> {
    config_dir("ratriyx").map(|dir| dir.join("config.toml"))
}

pub fn legacy_config_file() -> Option<PathBuf> {
    config_dir("nyxroute").map(|dir| dir.join("config.toml"))
}

/// Missing file means defaults. Loading never writes.
pub fn load(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = fs::read_to_string(path).map_err(io_err)?;
    Config::parse(&text)
}

/// Read-only description of what `config migrate` would do.
pub fn migration_preview(legacy: &Path, target: &Path) -> Result<String> {
    if !legacy.exists() {
        return Ok(format!("no legacy config at {}", legacy.display()));
    }
    if target.exists() {
        return Ok(format!(
            "{} exists and takes precedence; the legacy file is ignored",
            target.display()
        ));
    }
    let text = fs::read_to_string(legacy).map_err(io_err)?;
    Config::parse(&text)?;
    Ok(format!(
        "would copy {} to {} after validation; the original is kept",
        legacy.display(),
        target.display()
    ))
}

/// Opt-in copy of a validated legacy config. Never overwrites and never deletes.
pub fn migrate(legacy: &Path, target: &Path) -> Result<String> {
    if target.exists() {
        return Err(Error::Config(format!(
            "{} exists; not overwriting it",
            target.display()
        )));
    }
    let text = fs::read_to_string(legacy).map_err(io_err)?;
    Config::parse(&text)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(io_err)?;
    }
    atomic_write(target, text.as_bytes(), false)?;
    Ok(format!(
        "migrated to {}; the legacy file at {} is kept",
        target.display(),
        legacy.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_loopback() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.proxy_url(), "http://127.0.0.1:8118");
    }

    #[test]
    fn parses_example_config() {
        let text = r#"
            [proxy]
            host = "127.0.0.1"   # loopback only
            port = 8118

            [tor]
            socks_host = "127.0.0.1"
            socks_port = 9050
            control_enabled = false

            [runner]
            default_target = "opencode"
            mode = "per_process"
            require_tor = true

            [security]
            localhost_only = true
            verify_tls = true
        "#;
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.proxy_port, 8118);
        assert_eq!(cfg.default_target, "opencode");
    }

    #[test]
    fn non_loopback_proxy_is_refused() {
        let err = Config::parse("[proxy]\nhost = \"192.168.1.10\"\n").unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn disabling_tls_verification_is_refused() {
        let err = Config::parse("[security]\nverify_tls = false\n").unwrap_err();
        assert!(err.to_string().contains("verify_tls"));
    }

    #[test]
    fn fail_open_setting_is_refused() {
        assert!(Config::parse("[runner]\nrequire_tor = false\n").is_err());
    }

    #[test]
    fn unknown_key_is_an_error() {
        let err = Config::parse("[proxy]\nprot = 8118\n").unwrap_err();
        assert!(err.to_string().contains("unknown key proxy.prot"));
    }

    #[test]
    fn bad_port_reports_line() {
        let err = Config::parse("[proxy]\nport = 99999\n").unwrap_err();
        assert!(err.to_string().starts_with("line 2:"));
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let err = Config::parse("[proxy]\nport = 8118\nport = 8119\n").unwrap_err();
        assert!(err.to_string().contains("duplicate key"));
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("ratriyx-config-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn migration_keeps_the_original_and_refuses_to_overwrite() {
        let dir = scratch("migrate");
        let legacy = dir.join("nyxroute.toml");
        let target = dir.join("ratriyx").join("config.toml");
        fs::write(&legacy, "[proxy]\nport = 8118\n").unwrap();
        migrate(&legacy, &target).unwrap();
        assert!(legacy.exists(), "legacy file must be kept");
        assert_eq!(load(&target).unwrap(), Config::default());
        assert!(migrate(&legacy, &target).is_err(), "must not overwrite");
    }

    #[test]
    fn existing_ratriyx_config_takes_precedence_in_the_preview() {
        let dir = scratch("precedence");
        let legacy = dir.join("nyxroute.toml");
        let target = dir.join("config.toml");
        fs::write(&legacy, "[proxy]\nport = 8118\n").unwrap();
        fs::write(&target, "[proxy]\nport = 8118\n").unwrap();
        let preview = migration_preview(&legacy, &target).unwrap();
        assert!(preview.contains("takes precedence"));
    }

    #[test]
    fn corrupt_legacy_config_is_rejected_before_any_copy() {
        let dir = scratch("corrupt");
        let legacy = dir.join("nyxroute.toml");
        let target = dir.join("config.toml");
        fs::write(&legacy, "[security]\nverify_tls = false\n").unwrap();
        assert!(migration_preview(&legacy, &target).is_err());
        assert!(migrate(&legacy, &target).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn custom_socks_port_builds_its_own_forwarding_rule() {
        let cfg = Config {
            tor_socks_port: 9150,
            ..Config::default()
        };
        assert_eq!(cfg.desired_rule(), "forward-socks5t / 127.0.0.1:9150 .");
        let v6 = Config {
            tor_socks_host: "::1".into(),
            ..Config::default()
        };
        assert_eq!(v6.desired_rule(), "forward-socks5t / [::1]:9050 .");
    }

    #[test]
    fn empty_privoxy_path_is_refused() {
        assert!(Config::parse("[privoxy]\nconfig_path = \"\"\n").is_err());
    }

    #[test]
    fn ipv6_loopback_is_formatted_with_brackets() {
        let cfg = Config {
            proxy_host: "::1".into(),
            ..Config::default()
        };
        assert_eq!(cfg.proxy_url(), "http://[::1]:8118");
    }

    #[test]
    fn control_host_defaults_to_socks_host_and_accepts_override() {
        let cfg = Config::default();
        assert_eq!(cfg.tor_control_addr(), "127.0.0.1:9051");
        let split = Config {
            tor_socks_host: "::1".into(),
            tor_control_host: "127.0.0.1".into(),
            ..Config::default()
        };
        assert_eq!(split.tor_control_addr(), "127.0.0.1:9051");
        assert!(Config::parse("[tor]\ncontrol_host = \"192.168.1.10\"\n").is_err());
    }
}
