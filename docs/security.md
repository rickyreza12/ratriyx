# Security guide

Ratriyx reduces specific risks. It does not make your traffic anonymous. Read the limits before relying on it.

## What the code enforces

| Control | Where |
|---|---|
| Loopback only for proxy, SOCKS, and control endpoints | `config::validate`, `tor_control::newnym` |
| TLS certificate verification is never disabled | `config::validate` refuses `verify_tls = false`; curl runs with verification on |
| Fail-closed Tor mode: no launch without a verified route | `domain::route::decide`, `application::commands::launch::run` |
| Direct requests ignore ambient proxy variables | `network::fetch` (`--noproxy *` and removed variables) |
| No shell: program and arguments are passed as a list | `runner::run_child` |
| Interop launchers refused in Tor mode | `domain::route::decide`, `infrastructure::opencode::program_is_interop` |
| Secrets masked in text and JSON output, including Authorization headers | `redact::mask_value`, `redact::redact_text`, `diagnostics::render_*` |
| Tor cookie never printed; authentication errors show a code only | `tor_control::read_cookie`, `expect_ok` |
| Embedded HTTP proxy listens only on loopback; Tor control never exposed by Ratriyx | `embedded_proxy::start_on`, `tor_control` |
| Privileged actions need `--yes`; the plan type has no stop action | `service::control`, `privoxy::configure_file_for`, `recovery::apply` |
| Config edits: timestamped backup with mode/uid/gid, atomic write, hash-checked restore | `privoxy`, `fsutil` |
| Managed setup records owned files/services and rolls back failed verification | `managed`, `maintenance::setup_install` |
| Listener binds verified loopback-only, with process ownership where available | `service::listening`, `diagnostics::eval_listener` |
| NEWNYM serialized across processes with reserve-before-send | `tor_control::rotate` |
| Shell snapshot file is mode 0600 and never exported; per-session with `--session` | `shell::ensure_snapshot_for` |
| Only allowlisted units can be controlled; never kill by port | `service::validate` |
| curl ignores `~/.curlrc` (`-q`), so a user file cannot weaken TLS or add a proxy | `network::fetch` |
| Private files are created owner-only (0600 on Unix) from the first byte; Windows relies on the profile directory ACL until its runtime is verified | `fsutil::atomic_write` |
| Edited Privoxy config is checked before write and read back after; a mismatch puts the original back | `privoxy::configure_at_for`, `privoxy::validate_config_text` |

## Audit, 2026-10-15 (follow-up: cross-platform changes, static only)

Scope: `apps/src`, read in this pass. Method: code reading plus searches for `unsafe`, shell invocations, `--insecure`, and external commands. No live service, `/etc`, NEWNYM, or provider action was used.

| Area | Result |
|---|---|
| TLS | No path disables verification. Fixed: a user `.curlrc` could; `-q` now precedes all other curl options. |
| Loopback defaults | Proxy, SOCKS, and control addresses are validated as loopback; ratriyx opens only outbound connections. |
| Logs and JSON | Credentials in URLs are masked; the Tor cookie is never printed; covered by tests. |
| Backups | Fixed: temp files were created with the default mode and tightened afterwards. They are now created 0600, and a planted temp name is replaced instead of followed. Backups of `/etc/privoxy/config` keep a 0600 mode. |
| Child arguments | Passed as a list with no shell; ratriyx does not print them. |
| Bypasses | Privoxy rules that route destinations directly stop `configure`. Interop launchers are refused in Tor mode. Applications that ignore proxy variables are a documented limit. |
| Background servers | Warned about on every OpenCode launch; ratriyx cannot change a running server's environment. |
| External commands | `systemctl`, `ss`/`netstat`, `journalctl`, `chown`, and `curl` are found through `PATH`. A hostile `PATH` entry could substitute them. Accepted: the user's `PATH` already decides what runs. Upgrade path: absolute paths. |
| Supported claims | WSL2 is the tested target; plain Linux, Windows, and macOS are staged and labelled NOT VERIFIED until tested there. Unknown operating systems exit 3. |

Known gaps: Privoxy `--config-test` is not used as a gate because it exits 0 for an unknown directive. The check is structural instead (rule present, content read back). `configure --restart` validates, restarts, verifies, and rolls back, but the restart step itself needs approval and live verification per machine.

## Limits

1. **Anonymity is not guaranteed.** Tor is one layer. Logins, timing, and what you send still identify you.
2. **Accounts link requests.** A provider or site can correlate activity with an account regardless of IP address.
3. **Exit blocks.** Some sites block Tor exits. A block there is site behavior, not a proxy fault.
4. **Exit is not your ISP address.** A proxied request shows the Tor exit. An IP difference does not prove routing; `IsTor` is the signal.
5. **Applications may ignore proxy variables.** Ratriyx sets variables for HTTP(S) clients that read them. Plugins and programs that connect on their own can bypass the route.
6. **Other protocols are not routed.** The embedded HTTP proxy forwards ordinary HTTP and HTTPS CONNECT through Tor; raw UDP and arbitrary application traffic are not forced onto Tor.
7. **DNS.** Proxied names are resolved through Tor. Direct requests use the local resolver. A name resolved locally before a connection can leak.
8. **Running processes keep their environment.** A change in one shell does not reach a process that already started, including an OpenCode server.
9. **Platforms are separate.** WSL variables reach Windows only through `WSLENV`; native Windows uses its own config paths and process-scoped `$env:` variables. macOS uses Homebrew paths. Untested platforms are labelled, not claimed.
10. **Enforcement is limited.** Ratriyx verifies and refuses in its own launch path. It cannot force an arbitrary program onto Tor.
11. **Rate limits are not route problems.** A provider's HTTP 429 remains a provider limit. `rotate --yes` can request a Tor NEWNYM for circuit separation, subject to Tor cooldown and without an exit-IP guarantee. It does not retry provider requests or reset account quotas.

**Opt-in connection tracing:** `--trace-connections` on an owned embedded proxy
records only destination hostname/port and transport outcome during the child
run window. It does not record HTTP headers, URL paths, authorization tokens,
request/response bodies or prompts. Hostnames themselves may be private;
inspect output before copying or posting it. Application-phase counters exclude
Ratriyx's pre-launch verification probes. Connection metadata cannot prove
the absence of direct traffic, enforce a firewall or attribute every socket
to the intended child process.

## v0.4 desktop integration boundary

`ratriyx desktop serve` can run a loopback-only unauthenticated HTTP proxy for
local applications that have been explicitly configured to use it. Other
programs on the same computer may also reach that port. Only enable desktop
integrations when you trust local applications and the Tor SOCKS5 process.
The proxy must remain running while the current-user WinINet, PowerShell, or
Zed settings point to it. `desktop off` restores owned settings and refuses
to overwrite changed third-party configuration. This is not machine-wide
WinHTTP routing or a firewall, and it cannot protect identity sent to a service.
12. **Exit codes can be ambiguous.** A child can exit with 2 to 5 or with 128+N. Read the `ratriyx:` prefix on stderr to tell Ratriyx failures apart.

## Reporting a problem

Contact details and a disclosure process are not defined yet. Until they are, report privately to the maintainer rather than in a public issue.
