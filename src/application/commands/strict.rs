#[cfg(not(windows))]
use crate::domain::error::Error;
use crate::domain::error::Result;

/// A read-only capability check. Does not install firewall rules or provide
/// network protection. Exit status 0 means the WFP engine responded only.
pub fn check() -> Result<i32> {
    #[cfg(windows)]
    {
        say!("{}", crate::infrastructure::wfp_windows::preflight()?);
        say!("{}", crate::infrastructure::job_windows::preflight()?);
        say!("strict policy: NOT ACTIVE; application launch remains blocked");
        say!("missing: isolated process-tree identity, IPv4/IPv6+DNS rules, live leak tests");
        Ok(0)
    }
    #[cfg(not(windows))]
    {
        Err(Error::Unsupported(
            "WFP preflight only exists on Windows; strict mode is unavailable".into(),
        ))
    }
}
