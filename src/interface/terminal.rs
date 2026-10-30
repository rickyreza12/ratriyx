//! Terminal presentation. ANSI escape codes are emitted only to a real
//! terminal that has not opted out; redirected logs and JSON stay plain.
use crate::interface::diagnostics::{Check, Status};
use std::fmt::Write as _;
use std::io::{self, IsTerminal};

pub fn color_enabled() -> bool {
    io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").map_or(true, |term| term != "dumb")
}

fn accent(text: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

#[cfg(windows)]
pub fn install_header() {
    if crate::interface::installer::active() {
        return;
    }
    let color = color_enabled();
    eprintln!();
    eprintln!(
        "  {}",
        accent("R A T R I Y X   /   S E T U P", "1;36", color)
    );
    eprintln!(
        "  {}",
        accent("====================================", "2", color)
    );
    eprintln!("  Tor + embedded Rust proxy  |  loopback-only HTTP proxy");
    eprintln!(
        "  {}",
        accent("No changes to global Windows proxy settings", "2", color)
    );
    eprintln!();
}

/// Completion-oriented overall progress, not a fabricated download percentage.
#[cfg(windows)]
pub fn install_stage(index: usize, total: usize, description: &str) {
    if crate::interface::installer::stage(index, total, description) {
        return;
    }
    let color = color_enabled();
    let width = 20usize;
    let done = (index.saturating_sub(1) * width) / total.max(1);
    let bar = format!("{}{}", "#".repeat(done), "-".repeat(width - done));
    eprintln!(
        "  {} {}  {}",
        accent(&format!("[{bar}]"), "36", color),
        accent(&format!("{index}/{total}"), "1;36", color),
        description
    );
}

#[cfg(windows)]
pub fn install_done(description: &str) {
    if crate::interface::installer::done(description) {
        return;
    }
    eprintln!(
        "       {} {description}",
        accent("OK", "1;32", color_enabled())
    );
}

pub fn install_activity(label: &str, elapsed_secs: u64) {
    #[cfg(windows)]
    if crate::interface::installer::activity(label, elapsed_secs) {
        return;
    }
    eprintln!(
        "       {} {label} ({elapsed_secs}s elapsed)",
        accent("..", "33", color_enabled())
    );
}

#[cfg(windows)]
pub fn install_success(total: usize) {
    if crate::interface::installer::done("All stages completed; IsTor=true") {
        return;
    }
    eprintln!(
        "  {} {}",
        accent(&format!("[{}] ", "#".repeat(20)), "1;32", color_enabled()),
        accent(
            &format!("{total}/{total} complete - IsTor=true"),
            "1;32",
            color_enabled()
        )
    );
    eprintln!();
}

/// Captures setup logs in Ratatui, leaving structured non-TTY output intact.
pub fn install_log(message: &str) {
    #[cfg(windows)]
    if crate::interface::installer::log(message) {
        return;
    }
    eprintln!("  {message}");
}

/// True if a fullscreen dashboard has taken ownership of console output.
pub fn install_tui_active() -> bool {
    #[cfg(windows)]
    {
        crate::interface::installer::active()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Stream child output into the UI while keeping the fallback CLI unchanged.
pub fn install_stream(bytes: &[u8]) -> bool {
    #[cfg(windows)]
    if install_tui_active() {
        crate::interface::installer::ingest_output(bytes);
        return true;
    }
    let _ = bytes;
    false
}

/// Extract actual Curl progress percentages from a buffered progress meter.
pub fn install_curl_progress(bytes: &[u8]) {
    #[cfg(windows)]
    if install_tui_active() {
        crate::interface::installer::ingest_curl(bytes);
    }
    let _ = bytes;
}

fn heading(out: &mut String, label: &str, colorful: bool) {
    let _ = writeln!(
        out,
        "\n  {}",
        accent(&label.to_ascii_uppercase(), "1;36", colorful)
    );
    let _ = writeln!(
        out,
        "  {}",
        accent("-------------------------------------------", "2", colorful)
    );
}

/// Human-facing diagnostic display. Machine-readable --json and redirected
/// stdout always use the pre-existing stable, uncolored format.
pub fn doctor(checks: &[Check]) -> String {
    let colorful = io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").map_or(true, |term| term != "dumb");
    let mut out = String::new();
    let _ = writeln!(
        out,
        "  {}",
        accent("R A T R I Y X   /   D O C T O R", "1;36", colorful)
    );
    let _ = writeln!(out, "  Local proxy health and Tor verification");

    let mut categories: Vec<&str> = Vec::new();
    for item in checks {
        if !categories.contains(&item.category) {
            categories.push(item.category);
        }
    }
    for category in categories {
        heading(&mut out, category, colorful);
        for item in checks.iter().filter(|item| item.category == category) {
            let (symbol, hue) = match item.status {
                Status::Pass => ("PASS", "1;32"),
                Status::Warn => ("WARN", "1;33"),
                Status::Fail => ("FAIL", "1;31"),
                Status::NotTested => ("SKIP", "2"),
            };
            let _ = writeln!(
                out,
                "  {}  {}",
                accent(&format!("{symbol:<4}"), hue, colorful),
                crate::infrastructure::redact::redact_text(&item.evidence)
            );
            if let Some(step) = &item.next_step {
                let _ = writeln!(
                    out,
                    "        {} {}",
                    accent("NEXT:", "1;33", colorful),
                    crate::infrastructure::redact::redact_text(step)
                );
            }
        }
    }
    let pass = checks.iter().filter(|c| c.status == Status::Pass).count();
    let fail = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warn = checks.iter().filter(|c| c.status == Status::Warn).count();
    let skip = checks
        .iter()
        .filter(|c| c.status == Status::NotTested)
        .count();
    heading(&mut out, "summary", colorful);
    let summary = format!("{pass} pass  /  {fail} fail  /  {warn} warn  /  {skip} not tested");
    let _ = writeln!(
        out,
        "  {}",
        accent(&summary, if fail > 0 { "1;31" } else { "1;32" }, colorful)
    );
    if fail > 0 {
        let _ = writeln!(
            out,
            "  {}",
            accent("Tor routing is NOT currently verified.", "1;31", colorful)
        );
    } else if checks
        .iter()
        .any(|c| c.id == "tor.istor" && c.status == Status::Pass)
    {
        let _ = writeln!(
            out,
            "  {}",
            accent("Tor route verified: IsTor=true", "1;32", colorful)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_skips_color_when_disabled() {
        assert_eq!(accent("abc", "31", false), "abc");
        assert!(accent("abc", "31", true).contains("\x1b[31m"));
    }
}
