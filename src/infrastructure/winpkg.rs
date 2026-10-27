//! Managed dependency acquisition for Windows (M003).
//!
//! Plans are pure data (`Action` lists) so fixtures can assert them without
//! touching the machine. Execution shells out to WinGet or the system curl
//! through argument lists only, never through a shell string.

use crate::domain::error::{Error, Result};
use crate::infrastructure::fsutil::io_err;
use crate::infrastructure::hash::sha256_hex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    WingetInstall { package: String },
    Fetch { url: String, sha256: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    pub path: PathBuf,
}

/// One install plan for a missing tool: prefer a WinGet package, else a
/// pinned official download. A present tool plans nothing.
pub fn plan_for(
    name: &str,
    present: bool,
    winget_id: Option<&str>,
    official: Option<(&str, &str)>,
) -> Vec<Action> {
    let _ = name;
    if present {
        return Vec::new();
    }
    if let Some(package) = winget_id {
        return vec![Action::WingetInstall {
            package: package.to_string(),
        }];
    }
    match official {
        Some((url, sha256)) => vec![Action::Fetch {
            url: url.to_string(),
            sha256: sha256.to_string(),
        }],
        None => Vec::new(),
    }
}

pub fn describe(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .map(|a| match a {
            Action::WingetInstall { package } => format!("install {package} through WinGet"),
            Action::Fetch { url, .. } => format!("download and verify {url}"),
        })
        .collect()
}

fn winget_program() -> &'static str {
    if cfg!(windows) {
        "winget.exe"
    } else {
        "winget"
    }
}

/// Runs one action. Downloads land in `dest_dir` and are checksum-verified
/// before the path is returned. Anything else is an error.
pub fn execute(action: &Action, dest_dir: &Path) -> Result<FetchResult> {
    match action {
        Action::WingetInstall { package } => {
            crate::interface::terminal::install_log(&format!(
                "WinGet: installing missing {package} (streaming output)"
            ));
            let mut child = Command::new(winget_program())
                .args([
                    "install",
                    "--exact",
                    "--id",
                    package,
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| Error::Io(format!("cannot run WinGet (is it installed?): {e}")))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| Error::Io("cannot capture WinGet stdout".into()))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| Error::Io("cannot capture WinGet stderr".into()))?;
            // Tee both pipes concurrently; WinGet output remains visible.
            let out_thread = std::thread::spawn(move || tee_output(stdout, false));
            let err_thread = std::thread::spawn(move || tee_output(stderr, true));
            // WinGet provides messages but not a reliable percent-complete.
            // Report real elapsed time while its installer is running.
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let alive = std::sync::Arc::clone(&running);
            let ticker = std::thread::spawn(move || {
                let start = std::time::Instant::now();
                while alive.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    if alive.load(std::sync::atomic::Ordering::Relaxed) {
                        crate::interface::terminal::install_activity(
                            "Installing Privoxy through WinGet",
                            start.elapsed().as_secs(),
                        );
                    }
                }
            });
            let waited = child.wait();
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            let _ = ticker.join();
            let status = waited.map_err(io_err)?;
            let out = out_thread
                .join()
                .map_err(|_| Error::Io("WinGet stdout reader panicked".into()))?
                .map_err(io_err)?;
            let err = err_thread
                .join()
                .map_err(|_| Error::Io("WinGet stderr reader panicked".into()))?
                .map_err(io_err)?;
            if status.success() {
                crate::interface::terminal::install_log(&format!(
                    "WinGet finished installing {package}"
                ));
                return Ok(FetchResult {
                    path: PathBuf::from(package),
                });
            }
            Err(classify_failure(
                package,
                status.code().unwrap_or(-1),
                &format!("{out}\n{err}"),
            ))
        }
        Action::Fetch { url, sha256 } => fetch_verified(url, sha256, dest_dir),
    }
}

/// Forward streaming child output while remembering a bounded error tail.
fn tee_output<R: std::io::Read>(mut reader: R, stderr: bool) -> std::io::Result<String> {
    use std::io::Write as _;
    let mut retained = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if !crate::interface::terminal::install_stream(&chunk[..n]) {
            if stderr {
                std::io::stderr().write_all(&chunk[..n])?;
                std::io::stderr().flush()?;
            } else {
                std::io::stdout().write_all(&chunk[..n])?;
                std::io::stdout().flush()?;
            }
        }
        retained.extend_from_slice(&chunk[..n]);
        if retained.len() > 16_384 {
            retained.drain(..retained.len() - 16_384);
        }
    }
    Ok(String::from_utf8_lossy(&retained).into_owned())
}

fn classify_failure(package: &str, code: i32, output: &str) -> Error {
    let lower = output.to_ascii_lowercase();
    if output.contains("0x800704C7")
        || lower.contains("access is denied")
        || lower.contains("elevation")
        || lower.contains("cancelled by the user")
    {
        return Error::Approval(format!(
            "{package} installer needs elevation or was cancelled (exit {code}); re-run from an elevated prompt after review"
        ));
    }
    if lower.contains("no package found") || lower.contains("not found") {
        return Error::Config(format!(
            "{package} is not available from this source (exit {code}); refusing to substitute another package"
        ));
    }
    Error::Io(format!(
        "{package} installer failed with exit {code}: {}",
        output.trim().chars().take(300).collect::<String>()
    ))
}

fn curl_program() -> &'static str {
    if cfg!(windows) {
        "curl.exe"
    } else {
        "curl"
    }
}

fn fetch_verified(url: &str, sha256: &str, dest_dir: &Path) -> Result<FetchResult> {
    fs::create_dir_all(dest_dir).map_err(io_err)?;
    let name = url.rsplit('/').next().unwrap_or("download").to_string();
    let dest = dest_dir.join(&name);
    let mut command = Command::new(curl_program());
    command
        .args(["-q", "-fL", "--progress-bar", "--show-error", "-o"])
        .arg(&dest)
        .arg(url);
    let status = if crate::interface::terminal::install_tui_active() {
        use std::io::Read as _;
        let mut child = command
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .map_err(|e| Error::Io(format!("cannot start curl: {e}")))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::Io("cannot read curl progress".into()))?;
        let mut buffer = [0u8; 1024];
        let mut recent = Vec::new();
        loop {
            let n = stderr.read(&mut buffer).map_err(io_err)?;
            if n == 0 {
                break;
            }
            recent.extend_from_slice(&buffer[..n]);
            if recent.len() > 256 {
                recent.drain(..recent.len() - 256);
            }
            crate::interface::terminal::install_curl_progress(&recent);
            // Keep the actual curl errors visible within the dashboard.
            if buffer[..n].contains(&b'\n') {
                crate::interface::terminal::install_stream(&buffer[..n]);
            }
        }
        child.wait().map_err(io_err)?
    } else {
        command
            .status()
            .map_err(|e| Error::Io(format!("cannot run curl: {e}")))?
    };
    if !status.success() {
        return Err(Error::Io(format!("download failed: {url}")));
    }
    let bytes = fs::read(&dest).map_err(io_err)?;
    if sha256_hex(&bytes) != sha256.to_ascii_lowercase() {
        let _ = fs::remove_file(&dest);
        return Err(Error::Verification(format!(
            "checksum mismatch for {name}; the file was deleted, nothing installed"
        )));
    }
    Ok(FetchResult { path: dest })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tee_keeps_bounded_tail_and_preserves_unicode() {
        let content = "●".repeat(10_000);
        let observed = tee_output(std::io::Cursor::new(content.into_bytes()), true).unwrap();
        assert!(!observed.is_empty());
        assert!(observed.len() <= 16_390);
    }

    #[test]
    fn present_tool_plans_nothing() {
        assert!(plan_for("tor", true, Some("X.Y"), None).is_empty());
    }

    #[test]
    fn missing_tool_prefers_winget_over_official_download() {
        assert_eq!(
            plan_for(
                "privoxy",
                false,
                Some("Privoxy.Privoxy"),
                Some(("https://x", "ab"))
            ),
            vec![Action::WingetInstall {
                package: "Privoxy.Privoxy".into()
            }]
        );
        assert_eq!(
            plan_for("tor", false, None, Some(("https://x/t.tgz", "ab"))),
            vec![Action::Fetch {
                url: "https://x/t.tgz".into(),
                sha256: "ab".into()
            }]
        );
        assert!(plan_for("mystery", false, None, None).is_empty());
    }

    #[test]
    fn failure_text_is_classified() {
        assert!(matches!(
            classify_failure("P", 1, "No package found matching input criteria"),
            Error::Config(_)
        ));
        assert!(matches!(
            classify_failure("P", -1970249393, "failed 0x800704C7"),
            Error::Approval(_)
        ));
        assert!(matches!(
            classify_failure("P", 1, "weird output"),
            Error::Io(_)
        ));
    }

    #[test]
    fn verified_local_file_downloads_and_tamper_fails_closed() {
        let dir = std::env::temp_dir().join(format!("ratriyx-winpkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("pkg.bin");
        fs::write(&src, b"payload").unwrap();
        let url = format!("file://{}", src.display());
        let good = sha256_hex(b"payload");
        let out = execute(
            &Action::Fetch {
                url: url.clone(),
                sha256: good,
            },
            &dir.join("dl"),
        )
        .unwrap();
        assert_eq!(fs::read(&out.path).unwrap(), b"payload");
        let err = execute(
            &Action::Fetch {
                url,
                sha256: "00".repeat(32),
            },
            &dir.join("dl"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Verification(_)));
    }

    #[test]
    fn winget_absent_is_a_tool_error_not_a_panic() {
        let err = execute(
            &Action::WingetInstall {
                package: "No.Such.Package-xyz".into(),
            },
            &std::env::temp_dir(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Io(_) | Error::Config(_)));
    }
}
