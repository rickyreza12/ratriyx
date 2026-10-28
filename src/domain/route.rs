#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Direct,
    Tor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    Require,
    Allow,
}

pub const PROXY_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

pub const LOOPBACK_NO_PROXY: &str = "localhost,127.0.0.1,::1";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvPlan {
    pub set: Vec<(String, String)>,
    pub unset: Vec<String>,
}

/// Environment changes for one mode. Applies to a child process or a generated shell snippet only.
pub fn mode_env(mode: Mode, proxy_url: &str) -> EnvPlan {
    match mode {
        Mode::Direct => EnvPlan {
            set: Vec::new(),
            unset: PROXY_VARS.iter().map(|s| s.to_string()).collect(),
        },
        Mode::Tor => {
            let mut set: Vec<(String, String)> = [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "http_proxy",
                "https_proxy",
                "ALL_PROXY",
                "all_proxy",
            ]
            .iter()
            .map(|name| (name.to_string(), proxy_url.to_string()))
            .collect();
            set.extend(
                ["NO_PROXY", "no_proxy"]
                    .iter()
                    .map(|name| (name.to_string(), LOOPBACK_NO_PROXY.to_string())),
            );
            EnvPlan {
                set,
                unset: Vec::new(),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Verified,
    Unverified,
    Direct,
    NotVerified,
}

impl Label {
    pub fn text(self) -> &'static str {
        match self {
            Label::Verified => "verified",
            Label::Unverified => "unverified",
            Label::Direct => "direct",
            Label::NotVerified => "not verified",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Launch(Label),
    Refuse(String),
}

/// Pre-launch decision. Tor mode never falls back to direct; interop launchers are refused
/// unless the user explicitly accepts an unverified route.
pub fn decide(mode: Mode, verify: Verify, route_verified: bool, interop: bool) -> Decision {
    match (mode, verify, route_verified, interop) {
        (Mode::Direct, _, _, false) => Decision::Launch(Label::Direct),
        (Mode::Direct, _, _, true) => Decision::Launch(Label::NotVerified),
        (Mode::Tor, Verify::Allow, _, true) => Decision::Launch(Label::Unverified),
        (Mode::Tor, Verify::Require, _, true) => Decision::Refuse(
            "the program is a Windows interop launcher; WSLENV decides which variables reach it, and ratriyx cannot verify that. Refusing Tor mode. Use --allow-unverified to run it labelled unverified".into(),
        ),
        (Mode::Tor, _, true, false) => Decision::Launch(Label::Verified),
        (Mode::Tor, Verify::Allow, false, false) => Decision::Launch(Label::Unverified),
        (Mode::Tor, Verify::Require, false, false) => Decision::Refuse(
            "Tor route not verified (HTTP proxy or IsTor check failed). Refusing to launch; there is no direct fallback. Run `ratriyx doctor --mode tor`".into(),
        ),
    }
}

/// Limits that ratriyx cannot change, shown whenever OpenCode is launched.
pub fn opencode_boundary_notes() -> [&'static str; 3] {
    [
        "an OpenCode server started earlier keeps its own environment; restart it to apply this route",
        "Zed and Windows PowerShell are separate processes; set their proxy settings there, not here",
        "plugins that open their own connections may ignore proxy variables",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY: &str = "http://127.0.0.1:8118";

    #[test]
    fn direct_mode_removes_every_proxy_variable() {
        let plan = mode_env(Mode::Direct, PROXY);
        assert!(plan.set.is_empty());
        assert_eq!(plan.unset.len(), 8);
        assert!(plan.unset.contains(&"http_proxy".to_string()));
    }

    #[test]
    fn tor_mode_sets_both_cases_and_loopback_bypass() {
        let plan = mode_env(Mode::Tor, PROXY);
        let get = |n: &str| {
            plan.set
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("HTTP_PROXY").as_deref(), Some(PROXY));
        assert_eq!(get("https_proxy").as_deref(), Some(PROXY));
        assert_eq!(get("NO_PROXY").as_deref(), Some(LOOPBACK_NO_PROXY));
        assert_eq!(get("no_proxy").as_deref(), Some(LOOPBACK_NO_PROXY));
        assert_eq!(get("ALL_PROXY").as_deref(), Some(PROXY));
        assert_eq!(get("all_proxy").as_deref(), Some(PROXY));
        assert!(plan.unset.is_empty());
    }

    #[test]
    fn tor_mode_refuses_unverified_route_without_opt_in() {
        assert!(matches!(
            decide(Mode::Tor, Verify::Require, false, false),
            Decision::Refuse(_)
        ));
        assert_eq!(
            decide(Mode::Tor, Verify::Allow, false, false),
            Decision::Launch(Label::Unverified)
        );
    }

    #[test]
    fn verified_tor_route_launches_labelled_verified() {
        assert_eq!(
            decide(Mode::Tor, Verify::Require, true, false),
            Decision::Launch(Label::Verified)
        );
    }

    #[test]
    fn interop_launcher_is_refused_in_tor_mode_and_labelled_in_direct_mode() {
        assert!(matches!(
            decide(Mode::Tor, Verify::Require, true, true),
            Decision::Refuse(_)
        ));
        assert_eq!(
            decide(Mode::Direct, Verify::Require, false, true),
            Decision::Launch(Label::NotVerified)
        );
        assert_eq!(
            decide(Mode::Direct, Verify::Require, false, false),
            Decision::Launch(Label::Direct)
        );
    }

    #[test]
    fn loopback_bypass_covers_ipv4_and_ipv6() {
        let plan = mode_env(Mode::Tor, PROXY);
        let no_proxy = plan
            .set
            .iter()
            .find(|(k, _)| k == "NO_PROXY")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(no_proxy.contains("127.0.0.1"));
        assert!(no_proxy.contains("::1"));
        assert!(no_proxy.contains("localhost"));
    }

    #[test]
    fn opencode_boundary_notes_name_zed_powershell_and_plugins() {
        let notes = opencode_boundary_notes().join(" | ");
        assert!(notes.contains("Zed"));
        assert!(notes.contains("PowerShell"));
        assert!(notes.contains("plugins"));
        assert!(notes.contains("OpenCode server"));
    }
}
