use super::{validate, TorState, TOR_INSTANCE, TOR_MASTER};
use crate::domain::error::{Error, Result};
use std::collections::HashMap;
use std::process::Command;

/// Tor unit names to probe, in order. Debian uses `tor@default`; other
/// systemd setups may use plain `tor`.
const TOR_UNIT_CANDIDATES: [&str; 2] = [TOR_INSTANCE, TOR_MASTER];

/// Parses `systemctl show` output (`Key=Value` per line).
fn parse_show(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// The master `tor` unit can read `active (exited)` while the real instance is elsewhere,
/// so readiness is decided from the running instance alone.
fn eval_tor_state(
    unit: &str,
    instance: &HashMap<String, String>,
    master: &HashMap<String, String>,
) -> TorState {
    let active = instance.get("ActiveState").map(String::as_str) == Some("active");
    let sub = instance.get("SubState").cloned().unwrap_or_default();
    let master_state = format!(
        "{}/{}",
        master
            .get("ActiveState")
            .map(String::as_str)
            .unwrap_or("unknown"),
        master
            .get("SubState")
            .map(String::as_str)
            .unwrap_or("unknown")
    );
    TorState {
        instance_running: active && sub == "running",
        instance_sub: sub,
        master_state,
        unit: unit.to_string(),
    }
}

fn show(unit: &str, props: &str) -> Option<HashMap<String, String>> {
    let out = Command::new("systemctl")
        .args(["show", unit, "-p", props, "--no-pager"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| parse_show(&String::from_utf8_lossy(&out.stdout)))
}

/// Probe `tor@default` first, then plain `tor`. Returns the first unit that
/// answers `systemctl show`, preferring a running instance.
pub fn tor_state() -> Option<TorState> {
    let master = show(TOR_MASTER, "ActiveState,SubState").unwrap_or_default();
    let mut fallback: Option<TorState> = None;
    for unit in TOR_UNIT_CANDIDATES {
        if let Some(props) = show(unit, "ActiveState,SubState") {
            let state = eval_tor_state(unit, &props, &master);
            if state.instance_running {
                return Some(state);
            }
            if fallback.is_none() {
                fallback = Some(state);
            }
        }
    }
    fallback
}

pub fn unit_active(unit: &str) -> Option<bool> {
    show(unit, "ActiveState")
        .map(|props| props.get("ActiveState").map(String::as_str) == Some("active"))
}

/// Tor bootstrap percentage from journal text, if a `Bootstrapped` line exists.
pub fn parse_bootstrap_percent(journal: &str) -> Option<u8> {
    journal.lines().rev().find_map(|line| {
        let at = line.find("Bootstrapped ")?;
        let rest = &line[at + "Bootstrapped ".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u8>().ok()
    })
}

/// Read-only bootstrap probe. Returns None when the journal is unavailable.
pub fn tor_bootstrap_percent() -> Option<u8> {
    let out = Command::new("journalctl")
        .args(["-u", TOR_INSTANCE, "-n", "50", "--no-pager"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_bootstrap_percent(&String::from_utf8_lossy(&out.stdout))
}

/// `status` is read-only. Start, stop, and restart need `--yes` and run `systemctl` for one allowed unit.
pub fn control(action: &str, unit: &str, yes: bool) -> Result<String> {
    validate(action, unit)?;
    if action == "status" {
        let state = unit_active(unit)
            .map(|active| if active { "active" } else { "not active" })
            .unwrap_or("unknown (systemctl unavailable)");
        return Ok(format!("{unit}: {state}"));
    }
    if !yes {
        return Err(Error::Approval(format!(
            "systemctl {action} {unit} changes a running service; review it, then re-run with --yes"
        )));
    }
    if cfg!(windows) {
        return Err(Error::Unsupported(
            "Windows service control is not implemented in this build; manage Tor and Privoxy with the provided PowerShell scripts".into(),
        ));
    }
    let out = Command::new("systemctl")
        .args([action, unit])
        .output()
        .map_err(|e| Error::Io(format!("cannot run systemctl: {e}")))?;
    if out.status.success() {
        Ok(format!("systemctl {action} {unit}: done"))
    } else {
        Err(Error::Io(format!(
            "systemctl {action} {unit} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_exited_does_not_count_as_running_instance() {
        let instance = parse_show("ActiveState=inactive\nSubState=dead\n");
        let master = parse_show("ActiveState=active\nSubState=exited\n");
        let state = eval_tor_state(TOR_INSTANCE, &instance, &master);
        assert!(!state.instance_running);
        assert_eq!(state.master_state, "active/exited");
    }

    #[test]
    fn running_instance_is_detected() {
        let instance = parse_show("ActiveState=active\nSubState=running\n");
        let state = eval_tor_state(TOR_INSTANCE, &instance, &HashMap::new());
        assert!(state.instance_running);
    }

    #[test]
    fn bootstrap_percent_reads_the_latest_line() {
        let journal = "tor[1]: Bootstrapped 80% (conn_done)\ntor[1]: Bootstrapped 100% (done)\n";
        assert_eq!(parse_bootstrap_percent(journal), Some(100));
        assert_eq!(parse_bootstrap_percent("no bootstrap here\n"), None);
    }

    #[test]
    fn stop_without_approval_is_refused_and_runs_nothing() {
        let err = control("stop", "tor@default", false).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }
}
