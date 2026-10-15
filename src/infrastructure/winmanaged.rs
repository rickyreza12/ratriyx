//! Ratriyx-managed Tor and Privoxy on Windows (M005-M007).
//!
//! When no healthy existing installation is found, Ratriyx downloads pinned
//! official artifacts, writes Ratriyx-owned loopback-only configuration, and
//! runs the daemons as tracked processes (PID files). It never registers
//! system services, never kills by port or bare name, and never overwrites
//! existing configuration.

use crate::domain::error::{Error, Result};
use crate::infrastructure::fsutil::io_err;
use crate::infrastructure::service::Listener;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pinned Tor Expert Bundle (stable). Version floats never.
pub const TOR_BUNDLE_VERSION: &str = "15.0.25";
pub const TOR_BUNDLE_URL: &str = "https://dist.torproject.org/torbrowser/15.0.25/tor-expert-bundle-windows-x86_64-15.0.25.tar.gz";
/// SHA-256 fetched once from the official dist over TLS, 2026-10-15.
/// Gap: the accompanying `.asc` was not GPG-verified (no key available here).
pub const TOR_BUNDLE_SHA256: &str =
    "c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252";
pub const PRIVOXY_WINGET_ID: &str = "Privoxy.Privoxy";

/// Ratriyx-owned torrc: loopback SOCKS and control, cookie authentication,
/// managed data directory. No secrets are written here; Tor creates the
/// cookie file itself.
pub fn torrc_text(data_dir: &Path, socks_port: u16, control_port: u16) -> String {
    format!(
        "# Managed by ratriyx. Do not edit by hand.\n\
         SocksPort 127.0.0.1:{socks_port}\n\
         ControlPort 127.0.0.1:{control_port}\n\
         CookieAuthentication 1\n\
         DataDirectory \"{}\"\n\
         Log notice file \"{}\"\n",
        data_dir.display(),
        data_dir.join("tor.log").display(),
    )
}

/// Minimal Ratriyx-owned Privoxy config: loopback listen, one forwarding rule.
pub fn privoxy_conf_text(proxy_port: u16, tor_socks: &str) -> String {
    format!(
        "# Managed by ratriyx. Do not edit by hand.\n\
         listen-address 127.0.0.1:{proxy_port}\n\
         forward-socks5t / {tor_socks} .\n"
    )
}

/// True when no listener owns `port`. Callers refuse managed starts otherwise.
pub fn port_free(listeners: &[Listener], port: u16) -> bool {
    crate::infrastructure::service::find_listener(listeners, port).is_none()
}

pub fn pid_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.pid"))
}

/// Ratriyx-managed dependency root. Windows only; elsewhere managed
/// installs are not implemented (T306/T307).
pub fn managed_base() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(|local| {
                PathBuf::from(local)
                    .join("Programs")
                    .join("Ratriyx")
                    .join("deps")
            })
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn tar_program() -> &'static str {
    if cfg!(windows) {
        "tar.exe"
    } else {
        "tar"
    }
}

/// Extracts a `.tar.gz` bundle. The archive itself was checksum-verified
/// before this runs; extraction refuses to overwrite an occupied directory.
pub fn extract_bundle(archive: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        return Err(Error::Config(format!(
            "{} exists; refusing to extract over it",
            dest.display()
        )));
    }
    fs::create_dir_all(dest).map_err(io_err)?;
    let out = Command::new(tar_program())
        .args(["-xzf"])
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .output()
        .map_err(|e| Error::Io(format!("cannot run tar: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::Io(format!(
            "extracting {} failed: {}",
            archive.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Waits up to `deadline_secs` for a SOCKS5 greeting. Polls, never hammers:
/// one attempt per second.
pub fn wait_for_socks(addr: &str, deadline_secs: u64) -> Result<()> {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    loop {
        if crate::infrastructure::network::socks5_greeting(addr).is_ok() {
            return Ok(());
        }
        if start.elapsed() >= Duration::from_secs(deadline_secs) {
            return Err(Error::Verification(format!(
                "no SOCKS5 answer at {addr} after {deadline_secs}s; refusing to continue"
            )));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Starts `exe` detached enough to outlive the setup command and records its
/// PID. The caller owns verification that the daemon came up.
pub fn spawn_tracked(exe: &Path, args: &[&str], pid_file: &Path) -> Result<u32> {
    if let Some(parent) = pid_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(io_err)?;
        }
    }
    let child = Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| Error::Io(format!("cannot start {}: {e}", exe.display())))?;
    let pid = child.id();
    fs::write(pid_file, pid.to_string()).map_err(io_err)?;
    std::mem::forget(child);
    Ok(pid)
}

fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        // Signal 0 performs error checking without delivering a signal.
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Stops the recorded PID only. A stale file is removed and reported, never
/// acted on. PID reuse across a reboot is the known residual risk: stop
/// verifies the PID is alive but cannot prove it is still our daemon, so
/// managed stops happen only right after managed starts or explicit approval.
pub fn stop_tracked(pid_file: &Path) -> Result<String> {
    let text = fs::read_to_string(pid_file).map_err(|e| {
        Error::Io(format!(
            "cannot read PID file {}: {}",
            pid_file.display(),
            e.kind()
        ))
    })?;
    let pid: u32 = text.trim().parse().map_err(|_| {
        Error::Io(format!(
            "PID file {} is corrupt; refusing to act on it",
            pid_file.display()
        ))
    })?;
    if !pid_alive(pid) {
        let _ = fs::remove_file(pid_file);
        return Ok("already stopped; stale PID file removed".into());
    }
    #[cfg(windows)]
    {
        let out = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output()
            .map_err(io_err)?;
        if out.status.success() {
            let _ = fs::remove_file(pid_file);
            return Ok(format!("stopped PID {pid}"));
        }
        Err(Error::Io(format!(
            "cannot stop PID {pid}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
    #[cfg(not(windows))]
    {
        let out = Command::new("kill")
            .arg(pid.to_string())
            .output()
            .map_err(io_err)?;
        if out.status.success() {
            let _ = fs::remove_file(pid_file);
            return Ok(format!("stopped PID {pid}"));
        }
        Err(Error::Io(format!("cannot stop PID {pid}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torrc_is_loopback_cookie_auth_and_quotes_spaced_paths() {
        let text = torrc_text(Path::new("C:\\My Dir\\Tor Data"), 9050, 9051);
        assert!(text.contains("SocksPort 127.0.0.1:9050"));
        assert!(text.contains("ControlPort 127.0.0.1:9051"));
        assert!(text.contains("CookieAuthentication 1"));
        assert!(text.contains("DataDirectory \"C:\\My Dir\\Tor Data\""));
        assert!(!text.contains("Password") && !text.contains("HashedControlPassword"));
    }

    #[test]
    fn privoxy_conf_listens_on_loopback_with_one_forward() {
        let text = privoxy_conf_text(8118, "127.0.0.1:9050");
        assert!(text.contains("listen-address 127.0.0.1:8118"));
        assert!(text.contains("forward-socks5t / 127.0.0.1:9050 ."));
        assert_eq!(text.matches("forward").count(), 1);
    }

    #[test]
    fn occupied_port_refuses_managed_start() {
        let busy = vec![Listener {
            addr: "127.0.0.1".into(),
            port: 9050,
            process: None,
        }];
        assert!(!port_free(&busy, 9050));
        assert!(port_free(&busy, 8118));
        assert!(port_free(&[], 9050));
    }

    #[test]
    fn bundle_extracts_and_refuses_occupied_dirs() {
        let dir = std::env::temp_dir().join(format!("ratriyx-winm-x{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src").join("tor.exe"), "stub").unwrap();
        let archive = dir.join("bundle.tar.gz");
        let tar_out = Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .arg("-C")
            .arg(dir.join("src"))
            .arg(".")
            .output()
            .unwrap();
        assert!(tar_out.status.success());
        let dest = dir.join("dest");
        extract_bundle(&archive, &dest).unwrap();
        let mut found = false;
        for entry in fs::read_dir(&dest).unwrap().flatten() {
            if entry.file_name() == "tor.exe" {
                found = true;
            }
        }
        assert!(found);
        assert!(extract_bundle(&archive, &dest).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn socks_wait_fails_closed_on_a_dead_port() {
        let err = wait_for_socks("127.0.0.1:1", 1).unwrap_err();
        assert!(err.to_string().contains("no SOCKS5 answer"));
    }

    #[test]
    fn socks_wait_passes_against_a_stub_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            if let Ok((mut stream, _)) = listener.accept() {
                let mut greeting = [0u8; 3];
                let _ = stream.read_exact(&mut greeting);
                let _ = stream.write_all(&[0x05, 0x00]);
            }
        });
        assert!(wait_for_socks(&addr, 5).is_ok());
    }

    #[test]
    fn stale_pid_file_is_removed_never_killed() {
        let dir = std::env::temp_dir().join(format!("ratriyx-winm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pid = dir.join("tor.pid");
        fs::write(&pid, "4000000000").unwrap();
        let msg = stop_tracked(&pid).unwrap();
        assert!(msg.contains("stale"));
        assert!(!pid.exists());
        assert!(stop_tracked(&pid).is_err());
    }

    #[test]
    fn corrupt_pid_file_is_never_acted_on() {
        let dir = std::env::temp_dir().join(format!("ratriyx-winm-c{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pid = dir.join("tor.pid");
        fs::write(&pid, "not-a-pid").unwrap();
        assert!(stop_tracked(&pid).is_err());
        assert!(pid.exists(), "corrupt file must be kept for inspection");
    }

    #[cfg(unix)]
    #[test]
    fn spawned_stub_is_tracked_then_stopped() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("ratriyx-winm-s{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("stub.pid");
        let pid = spawn_tracked(Path::new("sleep"), &["30"], &pid_file).unwrap();
        assert!(pid > 0);
        assert_eq!(
            fs::read_to_string(&pid_file).unwrap().trim(),
            pid.to_string()
        );
        std::thread::sleep(Duration::from_millis(200));
        let msg = stop_tracked(&pid_file).unwrap();
        assert!(msg.contains("stopped"));
        assert!(!pid_file.exists());
    }
}
