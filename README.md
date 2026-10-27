# Ratriyx

Per-process privacy routing through Tor and Privoxy, on Linux (WSL2 and plain Linux), native Windows, and macOS.

Ratriyx (command: `ratriyx`) does not implement Tor or Privoxy. It checks them, starts a child program with proxy variables set for that child only, and reports what it could and could not verify. Tor (The Onion Router) is an anonymity network that exposes a SOCKS5 proxy (a general-purpose proxy protocol). Privoxy is a local HTTP proxy that forwards to Tor.

## Installation and first run

The published version is v0.2.0. The upcoming v0.3.0 development branch adds a Ratatui installer and safer recovery from partial installs.

The normal CLI experience is:

```powershell
cargo install ratriyx
ratriyx            # Interactive first-run checks and consent-based setup
ratriyx doctor     # Safe to call directly from any shell/script
ratriyx ip         # Verifies the Tor exit separately from the direct IP
```

The bare `ratriyx` command offers to install and configure missing Tor/Privoxy
**only when run in an interactive terminal**. It previews the actions and
requires an explicit `y` or `yes` before proceeding. Declining saves a local
skip marker; `ratriyx setup --install` remains available later. Calls from
scripts, CI, and `ratriyx --help` never initiate installation. Windows uses
a pinned Tor bundle and WinGet Privoxy; Linux/macOS still require system
packages installed separately. A real Windows managed installation successfully reached `IsTor=true` on October 27, 2026; individual Windows environments must still be checked. Setup now displays a six-stage progress bar, Tor download percentage, and WinGet elapsed-time indicators for Privoxy. If Tor exits or times out, the installer preserves a diagnostic log at `%LOCALAPPDATA%\\ratriyx\\state\\setup-tor-stderr.log` rather than hiding the original failure. A Tor SOCKS5 listener is not proof of anonymity; final route verification requires `IsTor=true`.

## Windows native application routing in v0.3.0

Native Windows executables and npm command shims (such as curl.exe and opencode.cmd) now inherit Ratriyx's per-process proxy environment without being mistaken for WSL interoperability launchers. Windows executables launched from inside WSL, and Windows launching wsl.exe, are still treated as unverified cross-environment processes. Do not assume that every application, plugin or subprocess honors HTTP_PROXY, HTTPS_PROXY and ALL_PROXY; verify the application's own traffic.

## v0.4 strict-routing foundation (feature branch only)

A separate development branch adds the opt-in `ratriyx run --strict --mode tor -- ...`
CLI contract. **Strict mode is not yet available**: on every platform it
exits with code 3 without starting the child, because a real OS-enforced
network guard is required. It never silently falls back to ordinary
per-process proxy variables. Existing `run --mode tor` continues unchanged.

See [docs/strict-routing-v0.4.md](docs/strict-routing-v0.4.md) for
the Windows WFP, Linux namespace and macOS enforcement requirements, and the
two alternatives to Privoxy (embedded HTTP-to-SOCKS with C Tor or embedded Arti).

## Upcoming v0.3.0 Windows terminal installer

The Windows managed installer now waits for Tor network bootstrap to reach 100% before making its external IsTor request, with a bounded five-minute bootstrap window and live percentage updates. A ready SOCKS5 listener alone does not mean usable Tor circuits exist. Failed network verification stops only newly started processes and preserves owned Tor data for retry.

The Windows managed installer now uses Ratatui when launched from an interactive terminal. It shows a complete setup pipeline, verified-stage progress bars for Tor, Privoxy and route checks, and a live operation indicator. Curl exposes actual Tor download percentages. WinGet does not provide a reliable percentage for Privoxy installation, so Ratatui shows elapsed-time activity and live installer messages instead of an invented percentage. Existing Privoxy installations, including unknown-version WinGet registrations, are reused rather than upgraded automatically.

For command scripts, redirected output, or legacy terminals, the installer keeps a normal text-only fallback. Set RATRIYX_NO_TUI=1 to disable Ratatui explicitly, or NO_COLOR=1 to disable colors and fullscreen UI. No install or package upgrade happens without the normal approval flag.

## What it does

- `ratriyx doctor` runs layered checks (environment, Tor instance, listeners, forwarding, direct request, proxied request, `IsTor`, OpenCode resolution) and reports `PASS`, `WARN`, `FAIL`, or `NOT_TESTED` with the next step.
- `ratriyx ip` reports the direct address, the proxied exit, and the Tor verification signal separately.
- `ratriyx run -- <program>` starts a program with proxy variables for that child only. Tor mode verifies the route first and never falls back to direct.
- `ratriyx env` and `ratriyx off` print shell code for you to evaluate, with a snapshot of prior values.
- `ratriyx recover` previews a repair plan. It starts services only with `--apply --yes`.
- `ratriyx configure`, `restore`, `service`, `rotate`, `uninstall`, and `config migrate` are guarded: each privileged action needs `--yes`, and each keeps a backup or refuses.
- `ratriyx setup --install --yes` performs managed setup: appends the Privoxy rule with a backup, starts missing services, records ownership, verifies the route, and rolls back on failure. Missing Tor/Privoxy/curl stop with manual install steps.
- `ratriyx uninstall` asks separately whether to remove Ratriyx settings, the Ratriyx-owned Tor bundle, and Ratriyx-installed Privoxy. Each defaults to No; external dependencies are **never removed implicitly**. `ratriyx uninstall --yes` removes only settings; `ratriyx uninstall --yes --remove-tor --remove-privoxy` is an explicit scripted clean reset. Only dependencies recorded as installed by Ratriyx are eligible.
- `ratriyx uninstall --remove-managed --yes` is the legacy managed-file restore command, which refuses to discard dependency ownership metadata while managed dependencies remain. The CLI executable is managed separately by `cargo uninstall ratriyx`.
- Recovery for orphaned Privoxy packages: the interactive uninstall shows a separate, default-No prompt when WinGet has the exact package but Ratriyx has lost its ownership record. For scripts, use `ratriyx uninstall --yes --remove-untracked-privoxy`. This never stops a running untracked Privoxy process, never edits an unowned configuration, and does nothing without explicit approval.
- Interactive terminal output uses grouped, color-coded doctor results and overall install progress. Redirected diagnostic output and `doctor --json` stay stable and uncolored; set `NO_COLOR=1` to disable ANSI colors.

## What it does not do

- It does not make traffic anonymous. Account logins, timing, and destinations still identify you.
- It does not change system-wide proxy settings, PowerShell profiles, or Zed settings. Running applications keep the environment they started with.
- It does not stop unrelated services, kill processes by port, or retry rate-limited providers.
- It does not change IP addresses to get around a provider's rate limit. A provider 429 is reported as a provider limit.
- It does not claim a platform is supported until it passes acceptance tests there. See the platform table below.

## Platform support

| Platform | Status |
|---|---|
| Ubuntu on WSL2 | Tested target. |
| Plain Linux (systemd) | Implemented; acceptance NOT VERIFIED on a plain-Linux machine. |
| Native Windows (PowerShell) | Managed Tor + Privoxy install and `IsTor=true` verified on a Windows machine (2026-10-27); wider Windows compatibility and scripts not fully validated. |
| macOS (Homebrew) | Implemented; runtime NOT VERIFIED on macOS. |
| Other operating systems | Refused, exit 3. |

## Quick start (WSL)

```bash
cd apps
cargo build --release
./target/release/ratriyx doctor --mode tor
./target/release/ratriyx run --mode tor -- opencode
```

See [installation.md](installation.md) for the full setup and [troubleshooting.md](troubleshooting.md) for failures.

## Documents

- [installation.md](installation.md): install and first run (WSL2, plain Linux, Windows, macOS).
- [scripts/windows/](scripts/windows/): `Start-Proxy.ps1`, `Stop-Proxy.ps1`, `Status-Proxy.ps1`, `Rotate-Tor.ps1` (PowerShell 5.1; runtime NOT VERIFIED).
- [troubleshooting.md](troubleshooting.md): pointer to the detailed guide.
- [docs/architecture.md](docs/architecture.md): design, diagram, and platform support table.
- [docs/security.md](docs/security.md): enforced controls, limits, and the latest audit.
- [docs/proxy-recovery.md](docs/proxy-recovery.md): recovery workflow and error classes.
- [docs/troubleshooting.md](docs/troubleshooting.md): detailed symptom-to-cause guide.
- [CHANGELOG.md](CHANGELOG.md): what changed in each release.

## Status

Version 0.2.0 is the published release. Version 0.3.0 is under development. It builds and passes formatting, clippy with warnings denied, and the test suite in Ubuntu under WSL2. Live checks that were run, and the ones not run, are recorded in `../workspaces/doc/tasks.md`.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
