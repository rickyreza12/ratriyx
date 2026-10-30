use crate::infrastructure::opencode::find_on_path;
use crate::infrastructure::platform;
use crate::infrastructure::service;
use std::ffi::OsStr;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupFacts {
    pub platform: String,
    pub support: String,
    pub systemd: bool,
    pub tor_installed: bool,
    pub curl_installed: bool,
    pub package_manager: Option<&'static str>,
    pub tor_state: String,
}

fn detect_package_manager(path_var: &OsStr) -> Option<&'static str> {
    platform::package_managers()
        .iter()
        .copied()
        .find(|name| find_on_path(name, path_var).is_some())
}

pub fn gather(path_var: &OsStr, cfg: &crate::infrastructure::config::Config) -> SetupFacts {
    let platform = platform::detect();
    let systemd = platform.systemd;
    let tor_state = if cfg!(windows) {
        match crate::infrastructure::network::socks5_greeting(&cfg.tor_socks_addr()) {
            Ok(()) => "SOCKS5 listener responding".to_string(),
            Err(reason) => format!("SOCKS5 unavailable ({reason})"),
        }
    } else {
        match service::tor_state() {
            Some(s) if s.instance_running => format!("{} running ({})", s.unit, s.master_state),
            Some(s) => format!("{} not running ({})", s.unit, s.master_state),
            None => "unknown (service manager unavailable)".to_string(),
        }
    };
    SetupFacts {
        platform: platform.describe(),
        support: platform.support_level().to_string(),
        systemd,
        tor_installed: find_on_path("tor", path_var).is_some() || {
            #[cfg(windows)]
            {
                crate::infrastructure::winmanaged::managed_base().is_some_and(|base| {
                    base.join("tor").join("Tor").join("tor.exe").is_file()
                        && base.join("tor").join("torrc").is_file()
                })
            }
            #[cfg(not(windows))]
            {
                false
            }
        },
        curl_installed: find_on_path(platform::curl_program(), path_var).is_some(),
        package_manager: detect_package_manager(path_var),
        tor_state,
    }
}

/// Read-only preview of Tor setup. Privoxy remains available only for legacy removal.
pub fn report(facts: &SetupFacts) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "ratriyx setup (dry run; no changes made)");
    let _ = writeln!(out, "platform:        {}", facts.platform);
    let _ = writeln!(out, "support:         {}", facts.support);
    let _ = writeln!(out, "systemd:         {}", yes_no(facts.systemd));
    let _ = writeln!(out, "tor installed:   {}", yes_no(facts.tor_installed));
    let _ = writeln!(out, "curl installed:  {}", yes_no(facts.curl_installed));
    let _ = writeln!(
        out,
        "package manager: {}",
        facts.package_manager.unwrap_or("none found")
    );
    let _ = writeln!(out, "tor network:     {}", facts.tor_state);
    let _ = writeln!(
        out,
        "proxy backend:   embedded Rust HTTP proxy (temporary loopback port)"
    );
    let _ = writeln!(out, "proposed steps:");
    if !facts.tor_installed {
        if facts.platform.to_ascii_lowercase().contains("windows") {
            let _ = writeln!(out, "  1. download managed Tor after setup --install --yes");
        } else {
            let pm = facts.package_manager.unwrap_or("your package manager");
            let _ = writeln!(
                out,
                "  1. install missing Tor, for example: sudo {pm} install tor"
            );
        }
    } else {
        let _ = writeln!(out, "  1. Tor installed; nothing to download");
    }
    if facts.tor_state.contains("not running") {
        let _ = writeln!(out, "  2. start Tor: ratriyx setup --install --yes");
    } else if facts.tor_state.contains("running") {
        let _ = writeln!(out, "  2. Tor already running; nothing to start");
    } else {
        let _ = writeln!(
            out,
            "  2. inspect Tor readiness with ratriyx doctor --mode tor"
        );
    }
    let _ = writeln!(out, "  3. verify IsTor through an embedded HTTP proxy");
    let _ = writeln!(out, "nothing above runs without your explicit approval");
    out
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(installed: bool, _forwarding: &str, tor: &str) -> SetupFacts {
        SetupFacts {
            platform: "linux (WSL2), ubuntu".into(),
            support: "supported (tested target)".into(),
            systemd: true,
            tor_installed: installed,
            curl_installed: installed,
            package_manager: Some("apt-get"),
            tor_state: tor.into(),
        }
    }

    #[test]
    fn report_is_a_dry_run_and_names_approval() {
        let text = report(&facts(
            true,
            "desired rule present",
            "tor@default running (active/exited)",
        ));
        assert!(text.contains("no changes made"));
        assert!(text.contains("nothing above runs without your explicit approval"));
        assert!(text.contains("nothing to download"));
    }

    #[test]
    fn unknown_service_does_not_claim_tor_running() {
        let output = report(&facts(
            false,
            "desired rule present",
            "unknown (service manager unavailable)",
        ));
        assert!(output.contains("inspect Tor readiness"));
        assert!(!output.contains("Tor already running"));
    }

    #[test]
    fn missing_packages_get_a_manual_install_hint_not_an_action() {
        let text = report(&facts(
            false,
            "desired rule absent",
            "tor@default not running (inactive/dead)",
        ));
        assert!(text.contains("sudo apt-get install tor"));
        assert!(!text.contains("install tor privoxy"));
        assert!(text.contains("ratriyx setup --install --yes"));
    }
}
