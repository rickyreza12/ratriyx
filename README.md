# Ratriyx

Per-process privacy routing through Tor and Privoxy, on Linux (WSL2 and plain Linux), native Windows, and macOS.

Ratriyx (command: `ratriyx`) does not implement Tor or Privoxy. It checks them, starts a child program with proxy variables set for that child only, and reports what it could and could not verify. Tor (The Onion Router) is an anonymity network that exposes a SOCKS5 proxy (a general-purpose proxy protocol). Privoxy is a local HTTP proxy that forwards to Tor.

## What it does

- `ratriyx doctor` runs layered checks (environment, Tor instance, listeners, forwarding, direct request, proxied request, `IsTor`, OpenCode resolution) and reports `PASS`, `WARN`, `FAIL`, or `NOT_TESTED` with the next step.
- `ratriyx ip` reports the direct address, the proxied exit, and the Tor verification signal separately.
- `ratriyx run -- <program>` starts a program with proxy variables for that child only. Tor mode verifies the route first and never falls back to direct.
- `ratriyx env` and `ratriyx off` print shell code for you to evaluate, with a snapshot of prior values.
- `ratriyx recover` previews a repair plan. It starts services only with `--apply --yes`.
- `ratriyx configure`, `restore`, `service`, `rotate`, `uninstall`, and `config migrate` are guarded: each privileged action needs `--yes`, and each keeps a backup or refuses.
- `ratriyx setup --install --yes` performs managed setup: appends the Privoxy rule with a backup, starts missing services, records ownership, verifies the route, and rolls back on failure. Missing Tor/Privoxy/curl stop with manual install steps.
- `ratriyx uninstall --remove-managed --yes` restores recorded files and stops recorded services. Pre-existing installations are never recorded or removed.

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
| Native Windows (PowerShell 5.1) | Implemented; runtime NOT VERIFIED on Windows. Scripts in `scripts/windows/`. |
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

Version 0.1.0 is a first build. It builds and passes formatting, clippy with warnings denied, and the test suite in Ubuntu under WSL2. Live checks that were run, and the ones not run, are recorded in `../workspaces/doc/tasks.md`.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
