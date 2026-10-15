use crate::domain::error::{Error, Result};
use crate::domain::route::EnvPlan;
use std::process::{Command, ExitStatus};

pub fn apply_env(cmd: &mut Command, plan: &EnvPlan) {
    for name in &plan.unset {
        cmd.env_remove(name);
    }
    for (name, value) in &plan.set {
        cmd.env(name, value);
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Launches `program` directly, with no shell, and returns the child's exit status.
/// Failure to start is a pre-launch error (exit 1). Failure after start is `PostLaunch` (exit 70).
pub fn run_child(program: &str, args: &[String], plan: &EnvPlan) -> Result<i32> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    apply_env(&mut cmd, plan);
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::Io(format!("cannot start {program}: {e}")))?;
    finish(program, child.wait())
}

fn finish(program: &str, waited: std::io::Result<ExitStatus>) -> Result<i32> {
    let status = waited.map_err(|e| Error::PostLaunch(format!("lost track of {program}: {e}")))?;
    Ok(exit_code(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::route::{mode_env, Mode};
    use std::ffi::OsStr;

    const PROXY: &str = "http://127.0.0.1:8118";

    fn value_of(cmd: &Command, name: &str) -> Option<Option<String>> {
        cmd.get_envs()
            .find(|(k, _)| *k == OsStr::new(name))
            .map(|(_, v)| v.map(|s| s.to_string_lossy().to_string()))
    }

    #[test]
    fn lost_wait_is_a_post_launch_error_with_exit_70() {
        let err = finish("child", Err(std::io::Error::other("wait failed"))).unwrap_err();
        assert_eq!(err.exit_code(), 70);
        assert!(err.to_string().contains("lost track of child"));
    }

    #[test]
    fn child_command_receives_the_plan_and_no_others() {
        let mut cmd = Command::new("ignored");
        apply_env(&mut cmd, &mode_env(Mode::Direct, PROXY));
        assert_eq!(value_of(&cmd, "HTTP_PROXY"), Some(None));
        let mut cmd = Command::new("ignored");
        apply_env(&mut cmd, &mode_env(Mode::Tor, PROXY));
        assert_eq!(value_of(&cmd, "HTTPS_PROXY"), Some(Some(PROXY.to_string())));
        assert_eq!(value_of(&cmd, "ALL_PROXY"), Some(Some(PROXY.to_string())));
    }

    #[cfg(windows)]
    fn exit_seven() -> (&'static str, Vec<String>) {
        ("cmd", vec!["/C".into(), "exit 7".into()])
    }

    #[cfg(not(windows))]
    fn exit_seven() -> (&'static str, Vec<String>) {
        ("sh", vec!["-c".into(), "exit 7".into()])
    }

    #[test]
    fn child_exit_code_is_passed_through() {
        let (program, args) = exit_seven();
        assert_eq!(run_child(program, &args, &EnvPlan::default()).unwrap(), 7);
    }

    #[cfg(unix)]
    #[test]
    fn child_killed_by_signal_reports_128_plus_signal() {
        let args = vec!["-c".to_string(), "kill -TERM $$".to_string()];
        assert_eq!(
            run_child("sh", &args, &EnvPlan::default()).unwrap(),
            128 + 15
        );
    }

    #[test]
    fn missing_program_is_a_pre_launch_error() {
        let err =
            run_child("definitely-missing-program-xyz", &[], &EnvPlan::default()).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }
}
