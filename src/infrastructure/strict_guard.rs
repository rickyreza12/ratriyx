//! OS-enforced network isolation contract for ratriyx run --strict.
//!
//! HTTP(S) proxy environment variables are NOT a kill switch. An application
//! may ignore them, resolve DNS directly, or spawn another executable.
//! This module must never return a lease unless a tested OS-level guard is
//! actually installed before the child starts and remains active until it exits.
//!
//! Future backend requirements (see docs/strict-routing-v0.4.md):
//! - Protect executable and descendants without a launch-time race.
//! - Permit only the assigned loopback proxy for protected processes.
//! - Block IPv4, IPv6, DNS, UDP/QUIC and unapproved inherited sockets.
//! - Allow the separate Tor client process to reach its relays.
//! - Fail closed on enforcement loss and clean up only owned rules.
//!
//! Currently a deliberately nonfunctional guard, not a VPN/firewall.
use crate::domain::error::{Error, Result};

#[must_use = "dropping a strict-routing lease can remove network protection"]
pub struct StrictEnforcementLease {
    _private: (),
}

/// Refuse all platforms until the OS-specific enforcement backend is implemented.
pub fn acquire(_program: &str) -> Result<StrictEnforcementLease> {
    Err(Error::Unsupported(format!(
        "strict routing is not available on {}: OS-level application isolation has not been implemented and tested. Refusing to start the application rather than risk direct-IP or DNS leakage; ordinary Tor proxy mode remains available without --strict, but cannot guarantee leak prevention",
        std::env::consts::OS
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_guard_fails_closed_without_enforcement() {
        let err = match acquire("opencode") {
            Ok(_) => panic!("unsupported enforcement must never produce a lease"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::Unsupported(_)));
        assert!(err.to_string().contains("Refusing to start"));
    }

    #[test]
    fn program_names_cannot_bypass_enforcement() {
        for executable in ["opencode", "curl.exe", "node.exe", "powershell.exe"] {
            assert!(acquire(executable).is_err());
        }
    }
}
