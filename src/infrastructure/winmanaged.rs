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
/// managed data directory. Tor notices go to stderr, which the Ratriyx
/// launcher already captures to a diagnostic file. This avoids Tor opening
/// a second platform-specific log path during startup. No secrets are
/// written here; Tor creates the cookie file itself.
pub fn torrc_text(data_dir: &Path, socks_port: u16, control_port: u16) -> String {
    format!(
        "# Managed by ratriyx. Do not edit by hand.\n\
         SocksPort 127.0.0.1:{socks_port}\n\
         ControlPort 127.0.0.1:{control_port}\n\
         CookieAuthentication 1\n\
         DataDirectory \"{}\"\n\
         GeoIPFile \"{}\"\n\
         GeoIPv6File \"{}\"\n\
         Log notice stderr\n",
        torrc_path(data_dir),
        torrc_path(&data_dir.join("geoip")),
        torrc_path(&data_dir.join("geoip6")),
    )
}

/// Tor parses quoted paths with C-style escapes. Native Windows
/// backslashes such as \\U are not valid torrc escapes, so convert separators
/// to forward slashes on Windows. Keep POSIX paths unchanged.
fn torrc_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    #[cfg(windows)]
    {
        path.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        path.into_owned()
    }
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

/// Discover the Privoxy executable after WinGet installs it. Installers
/// cannot reliably update the running process's PATH, so check standard
/// machine and per-user locations without scanning arbitrary directories.
pub fn find_privoxy_exe(path_var: &std::ffi::OsStr) -> Option<PathBuf> {
    if let Some(found) = crate::infrastructure::opencode::find_on_path("privoxy", path_var) {
        return Some(found);
    }
    #[cfg(windows)]
    {
        for name in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            let Some(base) = std::env::var_os(name).filter(|v| !v.is_empty()) else {
                continue;
            };
            let base = PathBuf::from(base);
            for candidate in [
                base.join("Privoxy").join("privoxy.exe"),
                base.join("Programs").join("Privoxy").join("privoxy.exe"),
            ] {
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
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

/// WinGet may register an installed package with an Unknown version even
/// when it is absent from PATH. Never attempt a blind install/upgrade.
#[cfg(windows)]
pub fn winget_has_package(package: &str) -> bool {
    let output = Command::new("winget.exe")
        .args([
            "list",
            "--exact",
            "--id",
            package,
            "--accept-source-agreements",
            "--disable-interactivity",
        ])
        .output();
    match output {
        Ok(result) => installed_package_row(&String::from_utf8_lossy(&result.stdout), package),
        Err(_) => false,
    }
}

#[cfg(any(test, windows))]
fn installed_package_row(output: &str, package: &str) -> bool {
    output
        .lines()
        .any(|line| line.split_whitespace().any(|column| column == package))
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

/// Poll SOCKS5 until ready, printing elapsed time instead of hanging silently.
#[cfg(test)]
pub fn wait_for_socks(addr: &str, deadline_secs: u64) -> Result<()> {
    wait_for_socks_monitor(addr, deadline_secs, None, None, None)
}

/// Monitor the actual child process as well as its SOCKS5 listener. If Tor
/// crashes, report the startup stderr immediately instead of waiting 60s.
pub fn wait_for_socks_with_child(
    addr: &str,
    deadline_secs: u64,
    child: &mut std::process::Child,
    stderr_log: &Path,
    tor_log: &Path,
) -> Result<()> {
    wait_for_socks_monitor(
        addr,
        deadline_secs,
        Some(child),
        Some(stderr_log),
        Some(tor_log),
    )
}

fn last_lines(path: &Path) -> String {
    fs::read_to_string(path)
        .ok()
        .map(|text| {
            let mut tail: Vec<&str> = text.lines().rev().take(4).collect();
            tail.reverse();
            tail.join(" | ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "no log output captured".into())
}

fn wait_for_socks_monitor(
    addr: &str,
    deadline_secs: u64,
    mut child: Option<&mut std::process::Child>,
    stderr_log: Option<&Path>,
    tor_log: Option<&Path>,
) -> Result<()> {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut next_report = 0u64;
    let mut last_bootstrap = String::new();
    loop {
        if let Some(handle) = child.as_mut() {
            if let Some(exit) = handle.try_wait().map_err(io_err)? {
                let details = stderr_log.map(last_lines).unwrap_or_default();
                return Err(Error::Verification(format!(
                    "Tor exited before SOCKS5 started ({exit}); {details}; startup log: {}",
                    stderr_log.map_or_else(|| "unavailable".into(), |p| p.display().to_string())
                )));
            }
        }
        if crate::infrastructure::network::socks5_greeting(addr).is_ok() {
            crate::interface::terminal::install_log(&format!(
                "SOCKS5 listener {addr} ready after {}s",
                start.elapsed().as_secs()
            ));
            return Ok(());
        }
        let elapsed = start.elapsed().as_secs();
        if elapsed >= deadline_secs {
            let stderr = stderr_log.map(last_lines).unwrap_or_default();
            let notices = tor_log.map(last_lines).unwrap_or_default();
            return Err(Error::Verification(format!(
                "no SOCKS5 answer at {addr} after {deadline_secs}s; refusing to continue. \
Tor stderr: {stderr}; Tor notices: {notices}; startup log: {}",
                stderr_log.map_or_else(|| "unavailable".into(), |p| p.display().to_string())
            )));
        }
        if elapsed >= next_report {
            crate::interface::terminal::install_activity(
                &format!("Waiting for Tor SOCKS5 ({elapsed}/{deadline_secs}s)"),
                elapsed,
            );
            if let Some(log) = tor_log {
                if let Ok(contents) = fs::read_to_string(log) {
                    if let Some(line) = contents
                        .lines()
                        .rev()
                        .find(|line| line.contains("Bootstrapped "))
                    {
                        if line != last_bootstrap {
                            crate::interface::terminal::install_log(&format!(
                                "Tor: {}",
                                line.trim()
                            ));
                            last_bootstrap = line.to_string();
                        }
                    }
                }
            }
            next_report = elapsed + 5;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Starts `exe` detached enough to outlive the setup command and records its
/// PID. The caller owns verification that the daemon came up.
/// Tor's SOCKS listener comes up before its circuits are usable. Parse the
/// latest milestone rather than treating an open socket as bootstrap success.
#[cfg(any(windows, test))]
pub fn bootstrap_percent(log: &str) -> Option<u8> {
    log.lines().rev().find_map(|line| {
        let percentage = line.split_once("Bootstrapped ")?.1.split_once('%')?.0;
        percentage.parse::<u8>().ok().filter(|p| *p <= 100)
    })
}

#[cfg(windows)]
pub fn wait_for_bootstrap_with_child(
    child: &mut std::process::Child,
    log: &Path,
    deadline_secs: u64,
) -> Result<()> {
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let mut previous = None;
    let mut next_heartbeat = 0;
    loop {
        if let Some(exit) = child.try_wait().map_err(io_err)? {
            return Err(Error::Verification(format!(
                "Tor exited before bootstrap 100% ({exit}); last notices: {}; log: {}",
                last_lines(log),
                log.display()
            )));
        }
        let progress = fs::read_to_string(log)
            .ok()
            .and_then(|contents| bootstrap_percent(&contents));
        if progress != previous {
            if let Some(percent) = progress {
                crate::interface::terminal::install_log(&format!(
                    "Tor network bootstrap: {percent}%"
                ));
                crate::interface::installer::bootstrap(percent);
                if percent == 100 {
                    return Ok(());
                }
            }
            previous = progress;
        }
        let elapsed = started.elapsed().as_secs();
        if elapsed >= deadline_secs {
            return Err(Error::Verification(format!(
                "Tor SOCKS5 is listening but the network did not bootstrap to 100% within {deadline_secs}s (latest: {}%). Last notices: {}. Log: {}. This may indicate blocked or slow relays, or network consensus; routing cannot be claimed yet.",
                progress.unwrap_or(0), last_lines(log), log.display()
            )));
        }
        if elapsed >= next_heartbeat {
            crate::interface::terminal::install_activity(
                &format!(
                    "Tor bootstrap {}% ({elapsed}/{deadline_secs}s)",
                    progress.unwrap_or(0)
                ),
                elapsed,
            );
            next_heartbeat = elapsed + 5;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

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

/// Start a tracked process with durable, Ratriyx-owned stdout/stderr logs.
/// The caller keeps the Child handle to detect an early process exit.
pub fn spawn_tracked_logged(
    exe: &Path,
    args: &[&str],
    pid_file: &Path,
    log_path: &Path,
) -> Result<std::process::Child> {
    if let Some(parent) = pid_file.parent() {
        fs::create_dir_all(parent).map_err(io_err)?;
    }
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).map_err(io_err)?;
    }
    let log = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(log_path)
        .map_err(io_err)?;
    let stdout = log.try_clone().map_err(io_err)?;
    let mut child = Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .map_err(|e| Error::Io(format!("cannot start {}: {e}", exe.display())))?;
    if let Err(err) = fs::write(pid_file, child.id().to_string()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io_err(err));
    }
    Ok(child)
}

/// On Windows, verify that the PID file still points to the expected
/// executable before stopping anything. A PID can be reused after a reboot;
/// never kill a different process solely because its PID matches.
#[cfg(windows)]
pub fn stop_tracked_verified(
    pid_file: &Path,
    expected_exe: &Path,
    expected_config: &Path,
) -> Result<String> {
    if !pid_file.exists() {
        return Ok("no Ratriyx-tracked process to stop".into());
    }
    let pid_text = fs::read_to_string(pid_file).map_err(io_err)?;
    let pid: u32 = pid_text.trim().parse().map_err(|_| {
        Error::Verification(format!(
            "invalid tracked PID file {}; refusing to stop any process",
            pid_file.display()
        ))
    })?;
    let script = format!(
        "$ErrorActionPreference = 'Stop'; $p = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; if ($null -eq $p) {{ exit 3 }}; [Console]::Out.Write($p.ExecutablePath + '|' + $p.CommandLine)"
    );
    let query = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| Error::Io(format!("cannot verify PID {pid} identity: {e}")))?;
    if query.status.code() == Some(3) {
        fs::remove_file(pid_file).map_err(io_err)?;
        return Ok("tracked process already stopped; stale PID file removed".into());
    }
    if !query.status.success() {
        return Err(Error::Verification(format!(
            "could not verify process identity for PID {pid}; refusing to stop it"
        )));
    }
    let details = String::from_utf8_lossy(&query.stdout);
    let (actual, command_line) = details.split_once('|').ok_or_else(|| {
        Error::Verification("cannot inspect tracked process command line; refusing cleanup".into())
    })?;
    let config_arg = expected_config.to_string_lossy().to_ascii_lowercase();
    if !command_line.to_ascii_lowercase().contains(&config_arg) {
        return Err(Error::Verification(format!(
            "PID {pid} is not running with Ratriyx's managed configuration; refusing to stop it"
        )));
    }
    let actual_path = fs::canonicalize(actual.trim()).map_err(|_| {
        Error::Verification(format!(
            "PID {pid} executable path cannot be verified; refusing to stop it"
        ))
    })?;
    let expected_path = fs::canonicalize(expected_exe).map_err(io_err)?;
    if !actual_path
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected_path.to_string_lossy())
    {
        return Err(Error::Verification(format!(
            "PID {pid} does not belong to the expected Ratriyx-managed executable; refusing to stop it"
        )));
    }
    stop_tracked(pid_file)
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

    #[cfg(windows)]
    #[test]
    fn torrc_windows_paths_use_forward_slashes_and_quote_spaces() {
        let text = torrc_text(Path::new("C:\\My Dir\\Tor Data"), 9050, 9051);
        assert!(text.contains("SocksPort 127.0.0.1:9050"));
        assert!(text.contains("ControlPort 127.0.0.1:9051"));
        assert!(text.contains("CookieAuthentication 1"));
        assert!(text.contains(r#"DataDirectory "C:/My Dir/Tor Data""#));
        assert!(text.contains(r#"GeoIPFile "C:/My Dir/Tor Data/geoip""#));
        assert!(text.contains(r#"GeoIPv6File "C:/My Dir/Tor Data/geoip6""#));
        assert!(text.contains("Log notice stderr"));
        assert!(!text.contains("Log notice file"));
        assert!(!text.contains("C:\\My Dir"));
        assert!(!text.contains("Password") && !text.contains("HashedControlPassword"));
    }

    #[cfg(not(windows))]
    #[test]
    fn torrc_unix_paths_preserve_slashes_and_quote_spaces() {
        let text = torrc_text(Path::new("/home/user/space dir/data"), 9050, 9051);
        assert!(text.contains("SocksPort 127.0.0.1:9050"));
        assert!(text.contains("ControlPort 127.0.0.1:9051"));
        assert!(text.contains("CookieAuthentication 1"));
        assert!(text.contains(r#"DataDirectory "/home/user/space dir/data""#));
        assert!(text.contains("Log notice stderr"));
        assert!(!text.contains("Log notice file"));
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
    fn exited_child_is_reported_without_waiting_for_timeout() {
        let dir = std::env::temp_dir().join(format!("ratriyx-early-exit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pid = dir.join("child.pid");
        let log = dir.join("child.log");
        let (exe, args): (&str, &[&str]) = if cfg!(windows) {
            ("cmd", &["/C", "exit", "9"])
        } else {
            ("sh", &["-c", "exit 9"])
        };
        let mut child = spawn_tracked_logged(Path::new(exe), args, &pid, &log).unwrap();
        let err = wait_for_socks_with_child("127.0.0.1:1", 5, &mut child, &log, &log).unwrap_err();
        assert!(err.to_string().contains("Tor exited"));
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

    #[cfg(windows)]
    #[test]
    fn verified_stop_refuses_to_kill_an_unrelated_process() {
        let dir = std::env::temp_dir().join(format!("ratriyx-pid-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pid = dir.join("unrelated.pid");
        fs::write(&pid, std::process::id().to_string()).unwrap();
        let fake_exe = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("not-tor.exe");
        assert!(stop_tracked_verified(&pid, &fake_exe, Path::new("C:\\fake.cfg")).is_err());
        assert!(pid.is_file());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn winget_detects_unknown_installed_version_without_upgrade() {
        let example = "Name                  Id              Version Available Source\n\
Privoxy (remove only) Privoxy.Privoxy Unknown 4.1.0     winget";
        assert!(installed_package_row(example, "Privoxy.Privoxy"));
        assert!(!installed_package_row(example, "Other.Package"));
    }

    #[test]
    fn bootstrap_parser_reads_latest_milestone() {
        assert_eq!(bootstrap_percent(""), None);
        assert_eq!(bootstrap_percent("Bootstrapped 20% (onehop)"), Some(20));
        assert_eq!(
            bootstrap_percent("Bootstrapped 100% (done)\nBootstrapped 30% (retry)"),
            Some(30)
        );
        assert_eq!(
            bootstrap_percent("Bootstrapped 30% (loading)\n[warn] trying relay"),
            Some(30)
        );
        assert_eq!(bootstrap_percent("Bootstrapped 250% (bad)"), None);
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
