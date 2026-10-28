# Ratriyx

**A native Rust CLI for routing proxy-aware applications through Tor.**

[![Crates.io](https://img.shields.io/crates/v/ratriyx.svg)](https://crates.io/crates/ratriyx)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Ratriyx runs on Windows, Linux and macOS. It uses the **C Tor client** and an
**embedded Rust HTTP-to-SOCKS5 proxy** for ordinary per-process Tor routing.
Privoxy remains available as a legacy option and is still used by parts of the
managed setup and diagnostic workflow. No Docker or container runtime is needed.

**Current release:** [v0.4.1](https://crates.io/crates/ratriyx/0.4.1)
(October 28, 2026). This patch release refreshes the crate's README and
roadmap; the CLI features remain those introduced in v0.4.0.

> **Security boundary:** A successful `IsTor=true` check verifies the specific
> test request. Ratriyx cannot yet guarantee that every connection from an
> application or its subprocesses uses Tor. The `--strict` flag deliberately
> refuses to launch until a verified operating-system network guard exists.
> Account identity, cookies, requests and traffic patterns can still identify you.

## Install

You need Rust **1.88 or newer** to build the CLI. Install the published crate:

```sh
cargo install ratriyx --locked
ratriyx --version
ratriyx doctor
ratriyx ip
```

Run `ratriyx` interactively for the consent-based first-run setup. On Windows,
the installer can manage the C Tor bundle and install Privoxy using WinGet.
It waits for Tor bootstrap and verifies the route before treating it as ready.
On Linux and macOS, external Tor and legacy Privoxy services may need separate
installation. The default embedded proxy requires a working local Tor SOCKS5
listener (normally `127.0.0.1:9050`), but **does not require Privoxy for
`run --mode tor` or `ip`**.

Setup, configuration changes and removal of managed dependencies require
explicit approval. See [installation.md](installation.md) and
[Windows managed installation](docs/windows-managed-install.md).

## Quick start: route one application

Choose Tor mode explicitly when launching a program:

```sh
ratriyx run --mode tor -- opencode --standalone
```

Ratriyx starts a temporary loopback HTTP proxy, sends its connections to C Tor
through SOCKS5, verifies a Tor request, and gives the launched application
`HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`. It stops the temporary listener
when the command exits. This is **per-process proxy configuration**, not
OS-enforced traffic isolation. An application or plugin can ignore these
variables or use other network protocols.

Check the direct address and Tor exit separately:

```sh
ratriyx ip
ratriyx privacy check
```

For comparison with the original external HTTP proxy:

```sh
ratriyx ip --privoxy
ratriyx run --mode tor --privoxy -- opencode --standalone
```

`--allow-unverified` requires an explicit `--privoxy` selection. Prefer the
verified embedded route. Never treat an unverified route as private.

## Optional Windows desktop integration

The v0.4 desktop proxy is **opt-in**. It is useful for proxy-aware programs
started from PowerShell or editors. It does not change the Windows firewall or
enforce routing for unrelated applications.

**Terminal A:** start the native Rust proxy and leave it running:

```powershell
ratriyx desktop serve --port 8119
```

**Terminal B:** enable the profile matching the shell you actually use:

```powershell
# Windows PowerShell 5.1
ratriyx desktop on --target powershell --yes

# PowerShell 7+ (instead of the preceding command)
ratriyx desktop on --target pwsh --yes
```

Start a **new PowerShell window** and verify:

```powershell
$env:HTTPS_PROXY
curl.exe -q -sS --max-time 30 https://check.torproject.org/api/ip
```

The environment value should be `http://127.0.0.1:8119`, and the response
should include `"IsTor":true`. Test the exact application separately.

Other optional targets are `zed` (Zed settings) and `windows` (current-user
WinINet settings). Each requires `--yes`; the Windows target is **not**
system-wide WinHTTP routing. Existing programs do not automatically inherit
new settings. See [desktop integration details](docs/desktop-privacy-v0.4.md).

Windows profile discovery respects redirected Documents folders, including
OneDrive. A prior Ratriyx-managed block at the older, non-redirected location
can be migrated with backups. Unrecognized or edited blocks are refused.
When the foreground proxy is down, the managed PowerShell profile warns but
still sets proxy variables so clients respecting them do not silently go
direct. Applications ignoring proxies remain outside this protection.

**Restore settings before stopping Terminal A:**

```powershell
ratriyx desktop off --target powershell --yes
# Or use --target pwsh, zed, or windows, for each target you enabled.
```

Restoration is guarded: Ratriyx refuses to overwrite unexpected changes in
settings it does not own.

## Command reference

| Command | Purpose |
|---|---|
| `ratriyx doctor [--json]` | Diagnose Tor, legacy forwarding and platform readiness |
| `ratriyx ip [--privoxy]` | Compare direct IP, Tor exit and verified `IsTor` status |
| `ratriyx privacy check [--json]` | Report verified routing evidence and remaining privacy risks |
| `ratriyx run --mode tor -- PROGRAM` | Run a proxy-aware application through the embedded frontend |
| `ratriyx desktop serve --port 8119` | Start a foreground loopback HTTP proxy |
| `ratriyx desktop on\|off --target TARGET --yes` | Opt-in per-user integration and restoration |
| `ratriyx rotate status` | Inspect Tor control availability and local NEWNYM cooldown |
| `ratriyx rotate --yes` | Request future circuit separation, if Tor control is configured |
| `ratriyx strict check` | Read-only Windows enforcement prerequisite check, not active protection |
| `ratriyx setup --install --yes` | Approved managed dependency installation |
| `ratriyx recover` | Preview recovery actions before choosing `--apply --yes` |
| `ratriyx uninstall` | Interactive, ownership-aware settings and dependency removal |

Run `ratriyx --help` for the complete command and option list.

## What Ratriyx does not guarantee

- **No active strict firewall:** `run --strict` refuses to start applications
  instead of silently falling back to a weaker route. Windows WFP and Job
  Object readiness checks do not install a production network guard.
- **No blanket application isolation:** Raw TCP, UDP/QUIC, IPv6, direct DNS,
  background servers and subprocesses may bypass an environment proxy.
- **No anonymity guarantee:** Logins, tokens, cookies, content, fingerprints
  and timing can link requests regardless of Tor exit IP.
- **No provider quota bypass:** HTTP 429 is a provider-side rate limit.
  `NEWNYM` does not reset account quotas or guarantee a different exit.
- **No traffic interception:** A Windows desktop proxy setting affects
  applications that honor it. It does not secure other software automatically.

The full threat model is in [security.md](docs/security.md) and
[strict-routing-v0.4.md](docs/strict-routing-v0.4.md).

## Platform verification

| Platform | Evidence and current boundary |
|---|---|
| Native Windows | Managed Tor/Privoxy setup and embedded-proxy `IsTor=true` verified on a Windows machine. The redirected PowerShell profile fix has automated tests, but real-user migration and other desktop settings still need systematic live regression coverage. |
| Ubuntu on WSL2 | Tested development target. Windows executables invoked across WSL remain a separate, unverified boundary. |
| Plain Linux | Code paths implemented; end-to-end platform acceptance remains incomplete. |
| macOS | Code paths implemented; end-to-end macOS runtime acceptance remains incomplete. |

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

Live network tests require explicit local opt-in and running Tor services.
The regular test suite does not imply all platform or privacy acceptance tests
have passed.

## Documentation and next steps

- [What's next](docs/NEXT_STEPS.md): prioritized work, release criteria and test gates.
- [Architecture](docs/architecture.md): components and data flow.
- [Embedded proxy](docs/embedded-proxy-v0.4.md): HTTP/CONNECT behavior and limits.
- [Desktop integration](docs/desktop-privacy-v0.4.md): configuration and safe restoration.
- [Strict routing threat model](docs/strict-routing-v0.4.md): why strict mode refuses.
- [Security guide](docs/security.md): protections, caveats and reporting.
- [Troubleshooting](docs/troubleshooting.md): diagnosis and error recovery.
- [Changelog](CHANGELOG.md): release history.

## License

Dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
