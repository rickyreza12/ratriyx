//! Opt-in checks against the real Tor and Privoxy on this machine. Ignored by default.
//! Run with: RATRIYX_LIVE=1 cargo test --test live_optin -- --ignored

use std::process::Command;

#[test]
#[ignore = "live: needs Tor and Privoxy running; run with RATRIYX_LIVE=1 and --ignored"]
fn live_doctor_reports_the_tor_checks() {
    if std::env::var("RATRIYX_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_ratriyx"))
        .args(["doctor", "--mode", "tor"])
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
}
