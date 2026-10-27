use crate::domain::error::{Error, Result};
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslGen {
    Wsl1,
    Wsl2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceBackend {
    Systemd,
    Windows,
    Launchd,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub wsl: Option<WslGen>,
    pub distro: String,
    pub systemd: bool,
}

impl Platform {
    pub fn describe(&self) -> String {
        let mut text = self.os.clone();
        match self.wsl {
            Some(WslGen::Wsl1) => text.push_str(" (WSL1)"),
            Some(WslGen::Wsl2) => text.push_str(" (WSL2)"),
            None => {}
        }
        if !self.distro.is_empty() {
            text.push_str(&format!(", {}", self.distro));
        }
        text
    }

    pub fn service_backend(&self) -> ServiceBackend {
        match self.os.as_str() {
            "windows" => ServiceBackend::Windows,
            "macos" => ServiceBackend::Launchd,
            "linux" => {
                if self.systemd {
                    ServiceBackend::Systemd
                } else {
                    ServiceBackend::Unknown
                }
            }
            _ => ServiceBackend::Unknown,
        }
    }

    /// Staged support level. Real GO still needs platform acceptance tests.
    pub fn support_level(&self) -> &'static str {
        match self.os.as_str() {
            "linux" => match self.wsl {
                Some(WslGen::Wsl2) => "supported (tested target)",
                Some(WslGen::Wsl1) => "conditional: WSL1 networking differs; NOT VERIFIED",
                None => "conditional: plain Linux; NOT VERIFIED until tested",
            },
            "windows" => "conditional: native Windows; NOT VERIFIED until tested",
            "macos" => "conditional: macOS; NOT VERIFIED until tested",
            _ => "unsupported",
        }
    }
}

/// Parse a Linux kernel release into a WSL generation, if any.
pub fn parse_wsl_gen(osrelease: &str) -> Option<WslGen> {
    let lower = osrelease.to_ascii_lowercase();
    if !lower.contains("microsoft") {
        return None;
    }
    if lower.contains("wsl2") || lower.contains("microsoft-standard-wsl2") {
        Some(WslGen::Wsl2)
    } else {
        // Older WSL1 kernels contain "Microsoft" without the WSL2 marker.
        // Treat as WSL1 unless proven otherwise.
        Some(WslGen::Wsl1)
    }
}

/// Parse `/etc/os-release` ID value, unquoted.
pub fn parse_distro(os_release: &str) -> String {
    for line in os_release.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ID=") {
            return rest.trim_matches('"').trim().to_string();
        }
    }
    String::new()
}

pub fn detect() -> Platform {
    let os = std::env::consts::OS.to_string();
    if os == "linux" {
        let wsl = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|s| parse_wsl_gen(&s));
        let distro = std::fs::read_to_string("/etc/os-release")
            .map(|s| parse_distro(&s))
            .unwrap_or_default();
        let systemd = std::fs::read_to_string("/proc/1/comm")
            .map(|s| s.trim() == "systemd")
            .unwrap_or(false);
        Platform {
            os,
            wsl,
            distro,
            systemd,
        }
    } else {
        Platform {
            os,
            wsl: None,
            distro: String::new(),
            systemd: false,
        }
    }
}

/// Allow staged platforms. Unknown operating systems stop here with exit code 3.
pub fn require_supported(platform: &Platform) -> Result<()> {
    match platform.os.as_str() {
        "linux" | "windows" | "macos" => Ok(()),
        _ => Err(Error::Unsupported(format!(
            "ratriyx supports Linux (WSL2 and plain Linux), native Windows, and macOS; detected {}.",
            platform.describe()
        ))),
    }
}

/// Default Privoxy config path for this machine. Prefer files managed by
/// Ratriyx after first-run setup; keep existing legacy installations intact.
pub fn default_privoxy_path() -> String {
    if cfg!(windows) {
        if let Some(local) = env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            let local = PathBuf::from(local);
            let managed = local
                .join("Programs")
                .join("Ratriyx")
                .join("deps")
                .join("privoxy.conf");
            let legacy = local
                .join("Programs")
                .join("TorPrivoxy")
                .join("privoxy.conf");
            return if managed.exists() || !legacy.exists() {
                managed
            } else {
                legacy
            }
            .to_string_lossy()
            .to_string();
        }
        return r"C:\ProgramData\TorPrivoxy\privoxy.conf".to_string();
    }
    if cfg!(target_os = "macos") {
        for candidate in [
            "/opt/homebrew/etc/privoxy/config",
            "/usr/local/etc/privoxy/config",
            "/etc/privoxy/config",
        ] {
            if Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
        return "/opt/homebrew/etc/privoxy/config".to_string();
    }
    "/etc/privoxy/config".to_string()
}

/// Match the owned Tor data directory once managed setup has been completed.
/// Retain the documented legacy path when it already exists.
pub fn default_cookie_path() -> String {
    if cfg!(windows) {
        if let Some(local) = env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            let local = PathBuf::from(local);
            let managed = local
                .join("Programs")
                .join("Ratriyx")
                .join("deps")
                .join("tor")
                .join("Data")
                .join("control_auth_cookie");
            let legacy = local
                .join("Programs")
                .join("TorPrivoxy")
                .join("TorData")
                .join("control_auth_cookie");
            return if managed.exists() || !legacy.exists() {
                managed
            } else {
                legacy
            }
            .to_string_lossy()
            .to_string();
        }
        return r"C:\ProgramData\TorPrivoxy\TorData\control_auth_cookie".to_string();
    }
    if cfg!(target_os = "macos") {
        for candidate in [
            "/opt/homebrew/var/run/tor/control.authcookie",
            "/usr/local/var/run/tor/control.authcookie",
            "/run/tor/control.authcookie",
        ] {
            if Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
    }
    "/run/tor/control.authcookie".to_string()
}

pub fn curl_program() -> &'static str {
    if cfg!(windows) {
        "curl.exe"
    } else {
        "curl"
    }
}

/// Package managers to look for on PATH, in preference order. Used only to print install hints.
pub fn package_managers() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &["brew"]
    } else if cfg!(windows) {
        &["choco", "winget"]
    } else {
        &["apt-get", "dnf", "pacman"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl2_release_is_detected() {
        assert_eq!(
            parse_wsl_gen("6.18.33.2-microsoft-standard-WSL2\n"),
            Some(WslGen::Wsl2)
        );
    }

    #[test]
    fn wsl1_release_is_not_claimed_as_wsl2() {
        assert_eq!(parse_wsl_gen("4.4.0-19041-Microsoft\n"), Some(WslGen::Wsl1));
    }

    #[test]
    fn plain_linux_has_no_wsl_generation() {
        assert_eq!(parse_wsl_gen("6.8.0-52-generic\n"), None);
    }

    #[test]
    fn distro_id_is_unquoted() {
        assert_eq!(parse_distro("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), "ubuntu");
        assert_eq!(parse_distro("ID=\"debian\"\n"), "debian");
        assert_eq!(parse_distro("NAME=no id here\n"), "");
    }

    #[test]
    fn staged_platforms_are_allowed() {
        for os in ["linux", "windows", "macos"] {
            let p = Platform {
                os: os.into(),
                wsl: None,
                distro: String::new(),
                systemd: false,
            };
            assert!(require_supported(&p).is_ok(), "{os} should be allowed");
        }
    }

    #[test]
    fn unknown_os_is_rejected_with_exit_three() {
        let p = Platform {
            os: "freebsd".into(),
            wsl: None,
            distro: String::new(),
            systemd: false,
        };
        let err = require_supported(&p).unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn wsl2_is_the_tested_target_and_others_are_conditional() {
        let wsl2 = Platform {
            os: "linux".into(),
            wsl: Some(WslGen::Wsl2),
            distro: "ubuntu".into(),
            systemd: true,
        };
        assert!(wsl2.support_level().contains("supported"));
        let plain = Platform {
            os: "linux".into(),
            wsl: None,
            distro: "debian".into(),
            systemd: true,
        };
        assert!(plain.support_level().contains("NOT VERIFIED"));
        assert_eq!(plain.service_backend(), ServiceBackend::Systemd);
        let win = Platform {
            os: "windows".into(),
            wsl: None,
            distro: String::new(),
            systemd: false,
        };
        assert_eq!(win.service_backend(), ServiceBackend::Windows);
    }
}
