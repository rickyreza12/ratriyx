use crate::domain::error::{Error, Result};
use crate::infrastructure::config::Config;
use crate::infrastructure::desktop_profiles;
use crate::infrastructure::embedded_proxy::EmbeddedProxy;
use crate::infrastructure::network::{self, Route};
use crate::interface::cli::DesktopTarget;
use crate::interface::diagnostics::{verification_failure, VERIFY_URL};
use std::net::SocketAddr;
use std::time::Duration;

fn check_port(port: u16, cfg: &Config) -> Result<()> {
    if port < 1024 || port == cfg.tor_socks_port {
        return Err(Error::Config(
            "desktop proxy port must be >= 1024 and different from Tor SOCKS5".into(),
        ));
    }
    Ok(())
}

fn verify_url(url: &str) -> Result<()> {
    let probe = network::fetch(&Route::Proxy(url.to_string()), VERIFY_URL, 20);
    if let Some(reason) = verification_failure(&probe.outcome) {
        return Err(Error::Verification(format!(
            "desktop proxy at {url} is not verified through Tor ({reason}); configuration unchanged"
        )));
    }
    Ok(())
}

pub fn serve(cfg: &Config, port: u16) -> Result<i32> {
    check_port(port, cfg)?;
    let socks: SocketAddr = cfg
        .tor_socks_addr()
        .parse()
        .map_err(|_| Error::Config("invalid Tor SOCKS5 endpoint".into()))?;
    let _listener = EmbeddedProxy::start_on(socks, port)?;
    let url = format!("http://127.0.0.1:{port}");
    verify_url(&url)?;
    say!("ratriyx desktop proxy verified at {url}; foreground only. Keep this terminal open.");
    say!("Use another terminal: ratriyx desktop on --target windows|powershell|pwsh|zed --yes");
    say!(
        "Restore integrations with desktop off --target TARGET --yes before stopping this server."
    );
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

pub fn change(
    cfg: &Config,
    target: DesktopTarget,
    enable: bool,
    yes: bool,
    port: u16,
) -> Result<i32> {
    check_port(port, cfg)?;
    if !yes {
        return Err(Error::Approval(format!(
            "desktop {} {:?} uses current-user settings and may affect other apps. Start 'ratriyx desktop serve --port {port}' in a separate terminal. Re-run with --yes after reviewing.",
            if enable { "on" } else { "off" }, target
        )));
    }
    if enable {
        verify_url(&format!("http://127.0.0.1:{port}"))?;
    }
    let message = match target {
        DesktopTarget::Windows => {
            #[cfg(windows)]
            {
                if enable {
                    crate::infrastructure::desktop_windows::enable(port)?
                } else {
                    crate::infrastructure::desktop_windows::disable()?
                }
            }
            #[cfg(not(windows))]
            {
                return Err(Error::Unsupported(
                    "Windows current-user proxy integration requires Windows".into(),
                ));
            }
        }
        DesktopTarget::PowerShell => {
            desktop_profiles::change_powershell_profile(false, enable, port)?
        }
        DesktopTarget::Pwsh => desktop_profiles::change_powershell_profile(true, enable, port)?,
        DesktopTarget::Zed => {
            desktop_profiles::edit_zed(&desktop_profiles::zed_path()?, enable, port)?
        }
    };
    say!("{message}");
    say!("Existing processes do not automatically restart, and apps can ignore proxy settings.");
    Ok(0)
}
