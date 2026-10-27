# Changelog

All notable changes to Ratriyx are recorded here.

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
