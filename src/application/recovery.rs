use crate::domain::error::{Error, Result};
use crate::domain::route::Mode;
use crate::infrastructure::service;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub stale_proxy_vars: Vec<String>,
    pub tor_running: bool,
    pub privoxy_running: bool,
    pub forwarding_present: bool,
    pub istor: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionKind {
    ShellSnippet(String),
    ServiceStart(String),
    ConfigEdit(String),
    Note(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub kind: ActionKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub target: Mode,
    pub actions: Vec<Action>,
    pub scope: String,
    pub launch: Option<String>,
}

fn action(kind: ActionKind, reason: &str) -> Action {
    Action {
        kind,
        reason: reason.to_string(),
    }
}

/// Builds the plan. The plan has no action that stops a service, so direct recovery
/// cannot stop Tor and no path here stops anything.
pub fn plan(target: Mode, facts: &Facts) -> Plan {
    match target {
        Mode::Direct => {
            let mut actions = Vec::new();
            if !facts.stale_proxy_vars.is_empty() {
                actions.push(action(
                    ActionKind::ShellSnippet(format!("unset {}", facts.stale_proxy_vars.join(" "))),
                    "proxy variables are set in this shell; clear them here (bash shown)",
                ));
            }
            actions.push(action(
                ActionKind::Note(
                    "Tor and Privoxy are left as they are; direct mode does not need them stopped"
                        .into(),
                ),
                "no service action",
            ));
            actions.push(action(
                ActionKind::Note("Windows proxy settings, Zed's environment, and an already running OpenCode server keep their own settings and need a restart or manual change".into()),
                "outside this shell",
            ));
            Plan {
                target,
                actions,
                scope: "affects only this shell and new child processes; does not change Windows, Zed, or running servers".into(),
                launch: Some("ratriyx run --mode direct -- opencode".into()),
            }
        }
        Mode::Tor => {
            let mut actions = Vec::new();
            if !facts.tor_running {
                actions.push(action(
                    ActionKind::ServiceStart(service::TOR_INSTANCE.into()),
                    "the Tor instance is not running",
                ));
            }
            if !facts.privoxy_running {
                actions.push(action(
                    ActionKind::ServiceStart(service::PRIVOXY.into()),
                    "Privoxy is not running",
                ));
            }
            if !facts.forwarding_present {
                actions.push(action(
                    ActionKind::ConfigEdit("ratriyx configure --yes".into()),
                    "the Privoxy forwarding rule is missing; this edit is privileged and keeps a backup",
                ));
            }
            if facts.istor != Some(true) {
                actions.push(action(
                    ActionKind::Note(
                        "route not verified; the launch command is withheld until IsTor is true"
                            .into(),
                    ),
                    "verification",
                ));
            }
            let verified_now = facts.istor == Some(true) && facts.forwarding_present;
            Plan {
                target,
                actions,
                scope: "starts only the services listed above; never stops anything".into(),
                launch: verified_now.then(|| "ratriyx run --mode tor -- opencode".into()),
            }
        }
    }
}

pub fn render(plan: &Plan) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "recovery plan for {} target (dry run unless --apply)",
        match plan.target {
            Mode::Direct => "direct",
            Mode::Tor => "tor",
        }
    );
    for (i, act) in plan.actions.iter().enumerate() {
        let body = match &act.kind {
            ActionKind::ShellSnippet(s) => format!("shell: {s}"),
            ActionKind::ServiceStart(u) => format!("service start: {u} (needs --apply --yes)"),
            ActionKind::ConfigEdit(c) => format!("manual or privileged: {c}"),
            ActionKind::Note(n) => format!("note: {n}"),
        };
        let _ = writeln!(out, "{}. {body}\n   reason: {}", i + 1, act.reason);
    }
    let _ = writeln!(out, "scope: {}", plan.scope);
    match &plan.launch {
        Some(cmd) => {
            let _ = writeln!(out, "launch: {cmd}");
        }
        None => out.push_str("launch: withheld until the route is verified\n"),
    }
    out
}

/// Runs only the service starts, and only with `--apply --yes`. Everything else is reported as a manual step.
pub fn apply(plan: &Plan, yes: bool) -> Result<Vec<String>> {
    let starts: Vec<&String> = plan
        .actions
        .iter()
        .filter_map(|a| match &a.kind {
            ActionKind::ServiceStart(u) => Some(u),
            _ => None,
        })
        .collect();
    if !starts.is_empty() && !yes {
        return Err(Error::Approval(format!(
            "starting {} needs explicit approval; re-run with --apply --yes",
            starts
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let mut report = Vec::new();
    for act in &plan.actions {
        match &act.kind {
            ActionKind::ServiceStart(unit) => report.push(service::control("start", unit, yes)?),
            ActionKind::ShellSnippet(s) => report.push(format!("manual: run `{s}` in your shell")),
            ActionKind::ConfigEdit(c) => {
                report.push(format!("manual: run `{c}` after reviewing its dry run"))
            }
            ActionKind::Note(n) => report.push(format!("note: {n}")),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(tor: bool, privoxy: bool, forwarding: bool, istor: Option<bool>) -> Facts {
        Facts {
            stale_proxy_vars: vec!["HTTP_PROXY".into()],
            tor_running: tor,
            privoxy_running: privoxy,
            forwarding_present: forwarding,
            istor,
        }
    }

    #[test]
    fn direct_plan_never_starts_or_stops_services() {
        let p = plan(Mode::Direct, &facts(false, false, false, None));
        assert!(!p
            .actions
            .iter()
            .any(|a| matches!(a.kind, ActionKind::ServiceStart(_))));
        assert!(p
            .actions
            .iter()
            .any(|a| matches!(&a.kind, ActionKind::ShellSnippet(s) if s.contains("HTTP_PROXY"))));
    }

    #[test]
    fn tor_plan_asks_for_missing_services_and_withholds_launch_until_verified() {
        let p = plan(Mode::Tor, &facts(false, true, true, None));
        assert!(p
            .actions
            .iter()
            .any(|a| a.kind == ActionKind::ServiceStart("tor@default".into())));
        assert!(p.launch.is_none());
    }

    #[test]
    fn verified_tor_plan_offers_scoped_launch() {
        let p = plan(Mode::Tor, &facts(true, true, true, Some(true)));
        assert_eq!(
            p.launch.as_deref(),
            Some("ratriyx run --mode tor -- opencode")
        );
    }

    #[test]
    fn tor_recovery_with_everything_down_starts_only_and_edits_with_approval() {
        let p = plan(Mode::Tor, &facts(false, false, false, None));
        let starts = p
            .actions
            .iter()
            .filter(|a| matches!(a.kind, ActionKind::ServiceStart(_)))
            .count();
        assert_eq!(starts, 2);
        assert!(p
            .actions
            .iter()
            .any(|a| matches!(&a.kind, ActionKind::ConfigEdit(c) if c.contains("--yes"))));
        assert!(p.launch.is_none());
        let text = render(&p);
        assert!(text.contains("never stops anything"));
        assert!(text.contains("launch: withheld"));
    }

    #[test]
    fn unverified_route_withholds_launch_even_when_forwarding_exists() {
        let p = plan(Mode::Tor, &facts(true, true, true, Some(false)));
        assert!(p.launch.is_none());
    }

    #[test]
    fn direct_recovery_report_names_the_stale_server_boundary_and_keeps_tor() {
        let p = plan(Mode::Direct, &facts(true, true, true, Some(true)));
        let text = render(&p);
        assert!(text.contains("already running OpenCode server"));
        assert!(text.contains("left as they are"));
        let lower = text.to_lowercase();
        assert!(!lower.contains("stop tor") && !lower.contains("kill"));
    }

    #[test]
    fn direct_recovery_without_stale_variables_has_no_shell_snippet() {
        let mut f = facts(true, true, true, Some(true));
        f.stale_proxy_vars.clear();
        let p = plan(Mode::Direct, &f);
        assert!(!p
            .actions
            .iter()
            .any(|a| matches!(a.kind, ActionKind::ShellSnippet(_))));
    }

    #[test]
    fn apply_without_yes_runs_nothing() {
        let p = plan(Mode::Tor, &facts(false, true, true, None));
        let err = apply(&p, false).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }
}
