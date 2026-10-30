//! One disposable Tor client with its own data directory and SOCKS listener.
//! The Tor executable/GeoIP files are borrowed from the existing managed install.
//! The original managed Tor daemon and its configuration are never modified.
use crate::domain::error::{Error, Result};
use crate::infrastructure::{fsutil::io_err, winmanaged};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct IsolatedTor {
    child: Option<Child>,
    scratch: PathBuf,
    socks: SocketAddr,
}

impl IsolatedTor {
    pub fn socks(&self) -> SocketAddr {
        self.socks
    }

    pub fn start(excluded: &[IpAddr]) -> Result<Self> {
        use std::os::windows::process::CommandExt;

        let base = winmanaged::managed_base().ok_or_else(|| {
            Error::Config("LOCALAPPDATA is unavailable for the installed Tor bundle".into())
        })?;
        let bundle = base.join("tor");
        let exe = bundle.join("Tor").join("tor.exe");
        let geoip = bundle.join("Data").join("geoip");
        let geoip6 = bundle.join("Data").join("geoip6");
        if !exe.is_file() || !geoip.is_file() || !geoip6.is_file() {
            return Err(Error::Verification(
                "no installed managed Tor bundle; first use 'ratriyx setup --install --yes'".into(),
            ));
        }
        // Reserve an available loopback port, then release it for Tor to bind.
        // A port collision during the short handoff causes Tor startup to fail closed.
        let port = TcpListener::bind(("127.0.0.1", 0))
            .map_err(io_err)?
            .local_addr()
            .map_err(io_err)?
            .port();
        let socks: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .map_err(|_| Error::Config("invalid isolated Tor SOCKS port".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Io(e.to_string()))?
            .as_nanos();
        let scratch =
            std::env::temp_dir().join(format!("ratriyx-isolated-tor-{}-{now}", std::process::id()));
        // create_dir fails rather than opening/reusing someone else's directory.
        fs::create_dir(&scratch).map_err(io_err)?;
        let mut instance = Self {
            child: None,
            scratch,
            socks,
        };
        let torrc = instance.scratch.join("torrc");
        let log = instance.scratch.join("bootstrap.log");
        let config = torrc_text(
            &instance.scratch.join("data"),
            &geoip,
            &geoip6,
            port,
            excluded,
        )?;
        fs::write(&torrc, config).map_err(io_err)?;
        let check = Command::new(&exe)
            .args(["-f", &torrc.to_string_lossy(), "--verify-config"])
            .output()
            .map_err(|e| Error::Io(format!("isolated Tor config check could not start: {e}")))?;
        if !check.status.success() {
            return Err(Error::Verification(format!(
                "isolated Tor rejected its generated configuration: {}",
                String::from_utf8_lossy(&check.stderr).trim()
            )));
        }
        let stderr = fs::File::create(&log).map_err(io_err)?;
        let stdout = stderr.try_clone().map_err(io_err)?;
        let mut cmd = Command::new(&exe);
        cmd.arg("-f")
            .arg(&torrc)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        instance.child = Some(
            cmd.spawn()
                .map_err(|e| Error::Io(format!("cannot start isolated Tor: {e}")))?,
        );
        eprintln!("ratriyx: starting a separate local Tor instance on {socks}");
        let child = instance.child.as_mut().expect("child just started");
        winmanaged::wait_for_socks_with_child(&socks.to_string(), 90, child, &log, &log)?;
        winmanaged::wait_for_bootstrap_with_child(child, &log, 180)?;
        Ok(instance)
    }
}

impl Drop for IsolatedTor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Only the child handle created above can be stopped here; never
            // kill a shared Tor service by PID, port, image name or process scan.
            let _ = child.kill();
            let _ = child.wait();
        }
        // The scratch folder was freshly created by this instance alone.
        // Remove best effort after the Tor handle has been reaped.
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

fn quote_tor_path(path: &Path) -> Result<String> {
    let value = path.to_string_lossy().replace('\\', "/");
    if value.contains(['"', '\n', '\r']) {
        return Err(Error::Config(
            "Tor directory path contains unsupported characters".into(),
        ));
    }
    Ok(format!("\"{value}\""))
}

fn torrc_text(
    data: &Path,
    geoip: &Path,
    geoip6: &Path,
    socks_port: u16,
    excluded: &[IpAddr],
) -> Result<String> {
    let mut config = format!(
        "SocksPort 127.0.0.1:{socks_port}\nControlPort 0\nCookieAuthentication 0\nDataDirectory {}\nGeoIPFile {}\nGeoIPv6File {}\nLog notice stderr\n",
        quote_tor_path(data)?,
        quote_tor_path(geoip)?,
        quote_tor_path(geoip6)?
    );
    if !excluded.is_empty() {
        config.push_str("ExcludeExitNodes ");
        config.push_str(
            &excluded
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        config.push('\n');
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_tor_has_distinct_loopback_and_exit_exclusions() {
        let conf = torrc_text(
            Path::new(r"C:\Temp\alt\data"),
            Path::new(r"C:\Tor\geoip"),
            Path::new(r"C:\Tor\geoip6"),
            9150,
            &[
                "192.0.2.9".parse().unwrap(),
                "198.51.100.8".parse().unwrap(),
            ],
        )
        .unwrap();
        assert!(conf.contains("SocksPort 127.0.0.1:9150"));
        assert!(conf.contains("DataDirectory \"C:/Temp/alt/data\""));
        assert!(conf.contains("ExcludeExitNodes 192.0.2.9,198.51.100.8"));
        assert!(conf.contains("ControlPort 0"));
    }
}
