use crate::infrastructure::opencode::find_on_path;
use crate::infrastructure::platform;
use crate::infrastructure::privoxy::{self, FwState};
use crate::infrastructure::service;
use std::ffi::OsStr;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupFacts {
    pub platform: String,
    pub support: String,
    pub systemd: bool,
    pub tor_installed: bool,
    pub privoxy_installed: bool,
    pub package_manager: Option<&'static str>,
    pub forwarding: String,
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
    let privoxy_path = std::path::Path::new(&cfg.privoxy_config);
    let forwarding = match privoxy::read_effective_for(privoxy_path, &cfg.desired_rule()) {
        FwState::Present => "desired rule present".to_string(),
        FwState::Absent => "desired rule absent".to_string(),
        FwState::Conflicting(_) => "conflicting rules present".to_string(),
        FwState::Unreadable(msg) => format!("unreadable ({msg})"),
    };
    let tor_state = match service::tor_state() {
        Some(s) if s.instance_running => format!("{} running ({})", s.unit, s.master_state),
        Some(s) => format!("{} not running ({})", s.unit, s.master_state),
        None => "unknown (service manager unavailable)".to_string(),
    };
    SetupFacts {
        platform: platform.describe(),
        support: platform.support_level().to_string(),
        systemd,
        tor_installed: find_on_path("tor", path_var).is_some(),
        privoxy_installed: find_on_path("privoxy", path_var).is_some(),
        package_manager: detect_package_manager(path_var),
        forwarding,
        tor_state,
    }
}

/// Read-only preview. Ratriyx never installs packages; it prints the commands for you to review.
pub fn report(facts: &SetupFacts) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "ratriyx setup (dry run; no changes made)");
    let _ = writeln!(out, "platform:        {}", facts.platform);
    let _ = writeln!(out, "support:         {}", facts.support);
    let _ = writeln!(out, "systemd:         {}", yes_no(facts.systemd));
    let _ = writeln!(out, "tor installed:   {}", yes_no(facts.tor_installed));
    let _ = writeln!(
        out,
        "privoxy installed: {}",
        yes_no(facts.privoxy_installed)
    );
    let _ = writeln!(
        out,
        "package manager: {}",
        facts.package_manager.unwrap_or("none found")
    );
    let _ = writeln!(out, "privoxy forwarding: {}", facts.forwarding);
    let _ = writeln!(out, "tor instance:    {}", facts.tor_state);
    let _ = writeln!(out, "proposed steps (each needs your separate approval):");
    if !facts.tor_installed || !facts.privoxy_installed {
        let pm = facts.package_manager.unwrap_or("your package manager");
        let _ = writeln!(
            out,
            "  1. install missing packages yourself, for example: sudo {pm} install tor privoxy"
        );
    } else {
        let _ = writeln!(out, "  1. packages present; nothing to install");
    }
    if facts.forwarding == "desired rule present" {
        let _ = writeln!(out, "  2. forwarding already present; nothing to configure");
    } else {
        let _ = writeln!(
            out,
            "  2. configure forwarding: ratriyx configure --dry-run, then ratriyx configure --yes"
        );
    }
    if facts.tor_state.contains("not running") {
        let _ = writeln!(out, "  3. start Tor: ratriyx service start tor --yes");
    } else {
        let _ = writeln!(out, "  3. Tor already running; nothing to start");
    }
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

    fn facts(installed: bool, forwarding: &str, tor: &str) -> SetupFacts {
        SetupFacts {
            platform: "linux (WSL2), ubuntu".into(),
            support: "supported (tested target)".into(),
            systemd: true,
            tor_installed: installed,
            privoxy_installed: installed,
            package_manager: Some("apt-get"),
            forwarding: forwarding.into(),
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
        assert!(text.contains("nothing to install"));
    }

    #[test]
    fn missing_packages_get_a_manual_install_hint_not_an_action() {
        let text = report(&facts(
            false,
            "desired rule absent",
            "tor@default not running (inactive/dead)",
        ));
        assert!(text.contains("sudo apt-get install tor privoxy"));
        assert!(text.contains("ratriyx service start tor --yes"));
    }
}
