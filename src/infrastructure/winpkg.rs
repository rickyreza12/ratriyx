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
            let out = Command::new(winget_program())
                .args([
                    "install",
                    "--exact",
                    "--id",
                    package,
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ])
                .output()
                .map_err(|e| Error::Io(format!("cannot run WinGet (is it installed?): {e}")))?;
            if out.status.success() {
                return Ok(FetchResult {
                    path: PathBuf::from(package),
                });
            }
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            Err(classify_failure(
                package,
                out.status.code().unwrap_or(-1),
                &text,
            ))
        }
        Action::Fetch { url, sha256 } => fetch_verified(url, sha256, dest_dir),
    }
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
    let status = Command::new(curl_program())
        .args(["-fsSL", "-o"])
        .arg(&dest)
        .arg(url)
        .status()
        .map_err(|e| Error::Io(format!("cannot run curl: {e}")))?;
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
