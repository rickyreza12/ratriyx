# Changelog

All notable changes to Ratriyx are recorded here.

## Unreleased (after 0.4.1)

- Added opt-in `--trace-connections` to embedded Tor `run`, external `gateway run`, and no-VPS `gateway tor run`. Application-phase traces show only accepted proxy connections, hostname/port, SOCKS results and CONNECT status; verification probes are excluded. Includes focused tests for app-phase accounting, secret-free event formatting and failed-SOCKS behavior. Tracing cannot prove absence of direct connections.
- Added a no-VPS Windows `gateway tor check/run` route. It starts a disposable second local Tor instance with its own data directory and loopback SOCKS listener, excludes the currently verified Tor exit, verifies a distinct public IP for the Tor probe, and stops its own child on exit without changing the original managed Tor.
- Added opt-in `gateway check/run --socks 127.0.0.1:PORT` for a separately operated local SOCKS5 endpoint (for example an SSH tunnel to an owned VPS); verified egress must differ from direct and an optional excluded IP, and failures refuse to launch.
- Normal setup, recovery and diagnostics now use Tor plus a temporary embedded Rust HTTP proxy, without installing or starting Privoxy.
- Windows Tor-mode launches can restart a previously installed managed Tor bundle; initial bootstrap uses bounded retry for transient IsTor transport failures.
- `status`, `doctor`, `ip` and `run` inspect the embedded route; Tor launches report the verified exit IP when available, and direct launches may report their public IP.
- Windows child processes use an owned kill-on-close Job Object for lifetime cleanup when assignment succeeds; strict OS network isolation is still unavailable.
- Tor-mode shell snippets refuse because they cannot own the temporary proxy. Updated Windows setup/OpenCode docs and the opt-in live test.

## 0.4.1 (2026-10-28)

- Documentation and CI maintenance release to refresh the README displayed on crates.io.
- Added a prioritized `docs/NEXT_STEPS.md` roadmap and aligned v0.4 docs with the published implementation and security limitations.
- Fixed `clippy::needless_question_mark` (Linux) and `clippy::chunks_exact_to_as_chunks` (Windows) reported by Rust 1.99 CI with `-D warnings`.
- No change to the v0.4.0 command behavior.

## 0.4.0 (2026-10-28)

- Fixed Windows PowerShell 5.1/7 profile discovery on redirected Documents folders (including OneDrive) using the Windows Known Folder API. Enabling the profile now migrates and backs up the previous Ratriyx-managed block from the legacy USERPROFILE path without overwriting unrelated user settings.
- PowerShell profiles now retain the configured proxy variables when the proxy is temporarily unavailable and warn clearly instead of silently sending proxy-aware traffic directly.
- Added local privacy assessment that refuses to claim anonymity or hide application identity leakage.
- Added opt-in desktop HTTP proxy server with explicit, restorable Windows current-user, PowerShell profile and Zed integrations (development).
- Added read-only Tor circuit cooldown status and verified post-rotation checks through the embedded proxy, while preserving provider quota boundaries.

## 0.3.0 (2026-10-28)

### Embedded proxy (experimental)

- `run --mode tor` and `ip` use a temporary, loopback-only embedded Rust HTTP-to-SOCKS5 proxy by default, forwarding target names through Tor's SOCKS5 endpoint for remote DNS.
- `--privoxy` explicitly retains the legacy frontend for `run` and `ip`. Existing `--embedded-proxy` scripts continue to work.
- Embedded proxy supports HTTP requests with Content-Length and HTTPS CONNECT, refuses failed Tor connections, and verifies `IsTor=true` before launching a child.
- `--strict` continues to refuse to launch until OS-backed enforcement exists. Application logins, DNS outside the proxy, and applications bypassing environment proxy variables remain important limitations.

### Windows managed setup and terminal UX

- Added a Ratatui interactive Windows installer with total-stage and separate Tor, Privoxy and routing progress bars, streamed WinGet output, real Tor transfer percentage and indeterminate activity feedback for operations without percentage APIs.
- Reuses already-installed Privoxy even if it is not on PATH and WinGet reports an Unknown version. Never forces an unrequested upgrade.
- Adds separately confirmed untracked Privoxy WinGet cleanup for stale/missing dependency ownership records; normal uninstalls remain ownership-safe.
- Reuses intact Ratriyx-managed Tor binaries and its configuration across reinstall attempts; refuses incomplete or unowned directories.
- Waits for the actual Tor network bootstrap to reach 100% (up to five minutes) before checking the external IsTor service; displays real bootstrap percentages. Startup errors include the last Tor milestone and saved log path.
- Keeps verified, owned Tor/Privoxy files, downloaded consensus and package ownership metadata after network verification failures for resumable retries; rolls back only the processes started by that attempt.
- Explicitly points Tor to the GeoIP/GeoIPv6 files supplied in the official expert bundle to avoid ambiguous default paths.
- Windows live acceptance completed: fresh Tor bootstrap from 0% to 100%, Privoxy listener, IsTor=true, doctor 8 pass/0 fail, repeat setup idempotent.
- Continues to fail closed when ports are occupied or a configuration is unexpectedly edited. Only newly installed dependencies are recorded as owned.
- Improved Windows setup discovery, human-readable recovery hints and terminal experience; plain, redirected and machine-readable output remain supported.
- Fix native Windows process detection: Windows PE executables such as curl.exe and opencode.exe no longer get rejected as WSL interop. Invoking wsl.exe still requires explicit unverified approval; WSL-hosted Windows launchers remain fail-closed.
- Live Windows per-process launch acceptance: run --mode tor -- curl.exe ... returned IsTor=true with exit code 0.
- Resolve Windows npm CLI launchers from PATH by trying native .exe/.com, then .cmd/.bat shims before extensionless POSIX scripts; fixes run --mode tor -- opencode --version on Windows.
- Increased minimum Rust version to 1.88 due to Ratatui dependency requirements. Ratatui UI can be disabled with RATRIYX_NO_TUI or NO_COLOR.


## 0.2.0 (unreleased)

### First-run onboarding (new)

- Windows installer now streams curl download progress and WinGet messages, prints six numbered setup stages and SOCKS5 elapsed time, and reads Tor bootstrap notices when available.
- Tor early exit and timeout errors include the last startup logs; standard error is preserved in the Ratriyx state directory after rollback.
- Rollback never deletes a pre-existing managed directory or config, and ownership records are only committed after successful IsTor verification.

- Interactive bare-command wizard offers Tor/Privoxy installation only after showing the managed installation plan and receiving explicit yes. Non-interactive calls still show help and never install software.
- Persist a first-run configured/skipped marker in Ratriyx-owned state; uninstall clears it.
- Align Windows defaults with Ratriyx-managed Privoxy and Tor paths while respecting legacy installations; locate Privoxy after WinGet even if PATH has not refreshed.
- Report unknown Windows service status truthfully; require IsTor verification before claiming already healthy.
- CI now builds and tests on Windows as well as Ubuntu. Native Windows live acceptance remains pending.

Staged cross-platform release. WSL2 stays the tested target; plain Linux, native Windows (PowerShell 5.1), and macOS are implemented but NOT VERIFIED at runtime.

### Added

- Staged platform support: WSL2, plain Linux (systemd discovery, `tor@default` then `tor`), native Windows (LOCALAPPDATA paths, `netstat` listeners, `choco`/`winget` hints), macOS (Homebrew prefixes, `brew` hints, `launchctl` boundary).
- Windows scripts: `scripts/windows/Start-Proxy.ps1`, `Stop-Proxy.ps1`, `Status-Proxy.ps1`, `Rotate-Tor.ps1` (PowerShell 5.1; static checks in `tests/ps_scripts.rs`; runtime NOT VERIFIED).
- `privoxy.config_path` setting (`[proxy]` or `[privoxy]` section); doctor, status, configure, restore, setup, and recovery use one consistent path.
- Forwarding rule built from the configured SOCKS endpoint instead of a hardcoded target.
- `configure --restart`: validate, restart Privoxy, verify the route, roll back on failure.
- Listener checks keep bind addresses and process ownership; wildcard binds fail Tor mode.
- Tor bootstrap percentage check (NOT_TESTED when the journal is unavailable).
- OpenCode `service status` probe; server state appears in doctor evidence.
- NEWNYM cross-process lock with reserve-before-send; concurrent rotates refuse.
- `ip`, `status`, and failed post-NEWNYM verification exit nonzero.
- Per-session shell snapshots (`--session NAME`).
- Case-insensitive Authorization and Proxy-Authorization redaction.
- Platform and backend reporting in doctor and setup.
- Tor mode sets `ALL_PROXY`/`all_proxy` so tools that only read those variables stay routed.
- Optional `tor.control_host` setting; defaults to the SOCKS host when empty.
- `status` and `recover` verify the route with a 5-second timeout; launch and doctor keep 30 seconds.
- Corrupt rotate lock files block instead of self-clearing.
- Duplicate config keys are rejected; `#` inside escaped quotes no longer ends the line.
- `service` accepts the full `tor@default` unit name.

### Security

- Ownership (mode/uid/gid) recorded in Privoxy backup metadata and restored best-effort.
- Historical live scripts quarantined under `tests/manual/`; `check.sh` no longer modifies sources.

### Not yet

- Runtime acceptance on plain Linux, Windows, and macOS.
- Provider probe (opt-in).
- Privoxy `--config-test` gate: still exits 0 for unknown directives.

## 0.1.0 (unreleased)

First build. Renamed from the earlier NyxRoute working name; the old name remains only in the legacy config path used by `ratriyx config migrate`.

### Added

- `doctor`, `ip`, `status`, `run`, `env`, `on`, `off`, `recover`, `setup --dry-run`, `configure`, `service`, `restore`, `uninstall`, `rotate`, `config migrate`.
- Direct and Tor run modes with fail-closed verification, `--allow-unverified`, and interop-launcher refusal.
- Privoxy forwarding detection, guarded append with backup, and hash-checked restore.
- Tor control over an authenticated cookie, on the TCP control port or a Unix `control_socket`, with a 10-second NEWNYM cooldown.
- Redaction of URL credentials and token-like values in text and JSON output.

### Security

- curl runs with `-q`, so a user `.curlrc` cannot weaken TLS or add a proxy.
- Private files are created 0600 from the first byte, and a planted temp-file symlink is replaced rather than followed.
- `configure` checks the edited text before writing and reads it back afterwards, putting the original back on a mismatch.

### Not yet

- Provider probe (opt-in).
- Privoxy restart step in `configure`. `privoxy --config-test` is not used as a gate: it exits 0 for an unknown directive.
- Parsing of included files: the installed Privoxy 3.0.34 manual documents no include directive for the main config.
- Native Windows and macOS support.

### Build notes

- No third-party crates. Decision recorded in `../workspaces/ratriyx/security.md` section 9 and `../workspaces/ratriyx/requirements.md`.
- Licensed `MIT OR Apache-2.0` (`LICENSE-MIT`, `LICENSE-APACHE`).
- Built and tested natively in Ubuntu under WSL2 with rustc and cargo 1.99.0. Check results are in `../workspaces/doc/tasks.md`.
