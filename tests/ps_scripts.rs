//! Static checks for the Windows PowerShell 5.1 scripts. These verify
//! content and syntaxlevel, not runtime behavior on Windows (NOT VERIFIED).
use std::path::PathBuf;

fn script(name: &str) -> String {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("scripts");
    dir.push("windows");
    dir.push(name);
    std::fs::read_to_string(&dir).unwrap_or_else(|_| panic!("missing script {name}"))
}

#[test]
fn all_four_windows_scripts_exist() {
    for name in [
        "Start-Proxy.ps1",
        "Stop-Proxy.ps1",
        "Status-Proxy.ps1",
        "Rotate-Tor.ps1",
    ] {
        assert!(!script(name).is_empty(), "{name} must not be empty");
    }
}

#[test]
fn scripts_avoid_powershell_7_only_syntax() {
    for name in [
        "Start-Proxy.ps1",
        "Stop-Proxy.ps1",
        "Status-Proxy.ps1",
        "Rotate-Tor.ps1",
    ] {
        let text = script(name);
        assert!(
            !text.contains("??"),
            "{name} must not use the PS7 null-coalescing operator"
        );
        assert!(!text.contains("?."), "{name} must not use ?. member access");
        assert!(
            !text.contains("-Parallel"),
            "{name} must not use ForEach-Object -Parallel"
        );
    }
}

#[test]
fn rotate_script_follows_the_control_protocol_contract() {
    let text = script("Rotate-Tor.ps1");
    for required in [
        "TcpClient",
        "AUTHENTICATE",
        "SIGNAL NEWNYM",
        "BeginConnect",
        "finally",
        "control_auth_cookie",
        "Length -ne 32",
    ] {
        assert!(
            text.contains(required),
            "Rotate-Tor.ps1 is missing {required}"
        );
    }
    assert!(
        !text.contains("$hex") || !text.contains("Write-Host $hex"),
        "Rotate-Tor.ps1 must never print the cookie"
    );
}

#[test]
fn stop_script_only_stops_tracked_processes() {
    let text = script("Stop-Proxy.ps1");
    assert!(text.contains(".pid"));
    assert!(!text.contains("kill"));
}
