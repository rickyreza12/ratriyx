//! Opt-in checks against a real Tor SOCKS5 listener and embedded proxy.
//! Run with RATRIYX_LIVE=1 and --ignored on a host with bootstrapped Tor.

use std::process::Command;

#[test]
#[ignore = "live: needs Tor SOCKS5 and external IsTor access; run with RATRIYX_LIVE=1 and --ignored"]
fn live_doctor_reports_the_tor_checks() {
    if std::env::var("RATRIYX_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_ratriyx"))
        .args(["doctor", "--mode", "tor", "--app", "opencode"])
        .output()
        .expect("ratriyx binary runs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("tor.istor"),
        "doctor must report the IsTor check"
    );
    assert!(
        text.contains("tor.socks"),
        "doctor must report the SOCKS check"
    );
    assert!(
        text.contains("proxy.embedded"),
        "doctor must test the embedded Rust proxy"
    );
    assert!(
        out.status.success() && text.contains("[PASS] tor.istor"),
        "live embedded Tor route failed: {text}"
    );
}
