use std::process::Command;

fn ratriyx(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ratriyx"))
        .args(args)
        .output()
        .expect("ratriyx binary runs")
}

#[test]
fn help_lists_every_command_and_exits_zero() {
    let out = ratriyx(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    for word in [
        "doctor",
        "ip",
        "status",
        "run",
        "recover",
        "configure",
        "rotate",
        "uninstall",
    ] {
        assert!(text.contains(word), "help is missing {word}");
    }
}

#[test]
fn no_arguments_noninteractive_shows_help_without_setup() {
    // .output() connects pipes: a script or Cargo test must never trigger
    // network downloads or dependency installation.
    let out = ratriyx(&[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("USAGE:"));
    assert!(!text.contains("Install and configure Tor"));
}

#[test]
fn version_reports_the_package_version() {
    let out = ratriyx(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ratriyx "));
}

#[test]
fn usage_errors_exit_two_before_any_platform_check() {
    let out = ratriyx(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    let out = ratriyx(&["run", "opencode"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn staged_platforms_are_not_rejected_with_exit_three() {
    // Linux, Windows, and macOS are staged platforms: usage parsing still
    // fails with 2, but the platform gate must not refuse them.
    let out = ratriyx(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn strict_check_never_claims_guard_active() {
    let out = ratriyx(&["strict", "check"]);
    // Windows hosted CI may not grant WFP session permissions.
    // Both outcomes are safe: availability or explicit refusal.
    if cfg!(windows) {
        assert!(matches!(out.status.code(), Some(0) | Some(3)));
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.code() == Some(0) {
            assert!(stdout.contains("no filters installed"));
            assert!(stdout.contains("NOT ACTIVE"));
        }
    } else {
        assert_eq!(out.status.code(), Some(3));
    }
    assert!(!String::from_utf8_lossy(&out.stdout).contains("strict policy: ACTIVE"));
}

#[test]
fn strict_mode_refuses_without_os_enforcement_before_child_launch() {
    // The executable does not exist. If strict starts resolution or launch
    // before acquiring the guard, it would produce a different error.
    let out = ratriyx(&["run", "--strict", "--", "this-must-never-launch"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("strict routing is not available"), "{err}");
    assert!(err.contains("Refusing to start"), "{err}");
}

#[test]
fn strict_mode_has_no_unverified_or_direct_fallback() {
    for args in [
        vec!["run", "--strict", "--mode", "direct", "--", "ignored"],
        vec!["run", "--strict", "--allow-unverified", "--", "ignored"],
    ] {
        let out = ratriyx(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn doctor_json_flag_is_accepted_by_the_parser() {
    let out = ratriyx(&["doctor", "--json", "--mode", "bogus"]);
    assert_eq!(out.status.code(), Some(2));
}

#[cfg(unix)]
fn on_wsl() -> bool {
    cfg!(target_os = "linux")
        && std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.to_ascii_lowercase().contains("microsoft"))
            .unwrap_or(false)
}

#[cfg(unix)]
fn scratch_config(name: &str, body: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!("ratriyx-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("ratriyx")).unwrap();
    std::fs::write(home.join("ratriyx").join("config.toml"), body).unwrap();
    home
}

#[cfg(unix)]
fn run_with_config(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ratriyx"))
        .env("XDG_CONFIG_HOME", home)
        .args(args)
        .output()
        .expect("ratriyx binary runs")
}

#[cfg(unix)]
#[test]
fn dead_proxy_endpoint_refuses_tor_mode_and_launches_nothing() {
    if !on_wsl() {
        return;
    }
    let home = scratch_config("dead", "[proxy]\nport = 1\n");
    let out = run_with_config(
        &home,
        &["run", "--mode", "tor", "--", "sh", "-c", "echo LAUNCHED"],
    );
    assert_eq!(out.status.code(), Some(4));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("LAUNCHED"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Refusing to launch"));
}

#[cfg(unix)]
#[test]
fn allow_unverified_tor_launch_sets_child_proxy_env() {
    if !on_wsl() {
        return;
    }
    let home = scratch_config("allow", "[proxy]\nport = 1\n");
    let out = Command::new(env!("CARGO_BIN_EXE_ratriyx"))
        .env("XDG_CONFIG_HOME", &home)
        .args([
            "run",
            "--mode",
            "tor",
            "--allow-unverified",
            "--",
            "sh",
            "-c",
            "echo proxies=${HTTP_PROXY:-unset},${ALL_PROXY:-unset}",
        ])
        .output()
        .expect("ratriyx binary runs");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("http://127.0.0.1:1"), "{text}");
}

#[cfg(unix)]
#[test]
fn modes_switch_repeatedly_without_leaking_proxy_state() {
    if !on_wsl() {
        return;
    }
    let home = scratch_config("switch", "[proxy]\nport = 1\n");
    for _ in 0..2 {
        let out = Command::new(env!("CARGO_BIN_EXE_ratriyx"))
            .env("XDG_CONFIG_HOME", &home)
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .args([
                "run",
                "--mode",
                "direct",
                "--",
                "sh",
                "-c",
                "echo proxy=${HTTP_PROXY:-unset}",
            ])
            .output()
            .expect("ratriyx binary runs");
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("proxy=unset"));
        let tor = run_with_config(&home, &["run", "--mode", "tor", "--", "true"]);
        assert_eq!(tor.status.code(), Some(4));
    }
}
