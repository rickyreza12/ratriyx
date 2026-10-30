# Troubleshooting Ratriyx

Run these read-only commands on the machine where routing is failing:

```powershell
ratriyx status
ratriyx ip
ratriyx doctor --mode tor --app opencode
```

Use `ratriyx doctor --mode tor --json` for a structured report. Tokens and URL credentials are redacted, but review diagnostics before sharing.

## Tor SOCKS5 listener unavailable

A Tor SOCKS5 handshake to the configured loopback port (default 9050) failed. On Windows, run `ratriyx setup --dry-run` to inspect whether managed Tor is installed. `ratriyx run --opencode --mode tor` can automatically start an already installed and owned managed Tor process. To approve the first installation, review `ratriyx setup --install`, then run `ratriyx setup --install --yes`.

On Linux check the Tor instance with the service manager. The systemd master service showing active does not prove Tor SOCKS5 is ready.

## Embedded proxy cannot start

The Rust proxy binds to a temporary loopback port. An error can indicate a local socket bind failure or a configured Tor SOCKS5 address error. No externally managed HTTP proxy on port 8118 is required.

## IsTor=false, timeouts or connection failures

Tor SOCKS5 can answer before its circuits finish building. Wait for Tor bootstrap, inspect the Tor diagnostic log, and run `ratriyx ip` again. The request to `https://check.torproject.org/api/ip` must report `IsTor=true` through the actual embedded proxy. Tor-required child launch refuses to proceed when that verification fails. A different direct IP is not sufficient proof of Tor routing.

## OpenCode cannot be found or reports a local server

Run `ratriyx doctor --mode tor --app opencode`. OpenCode should resolve to an executable on PATH. Windows npm command shims are supported; WSL interop paths require special care. An OpenCode background server started before route selection keeps its original network environment until restarted.

## Free usage limit reached, provider.quota, HTTP 429

The provider enforced a usage limit. This is independent of the Tor connectivity check. Ratriyx does not rotate accounts or bypass provider quota controls. Check the OpenCode provider quota, account, and plan.

## Verify whether OpenCode actually used the proxy

Run `ratriyx gateway tor run --trace-connections --opencode -- --standalone` using the latest feature-branch binary. This starts a disposable local Tor client, then records **only** proxy connections after the app starts. Make one authorized model request in the OpenCode UI, and look for the provider hostname, `socks-connected`, and `CONNECT tunnel-established`. `accepted=0` means this bridge saw no app-phase connection; it is **not** proof of direct bypass without independent evidence that a request was sent. Avoid logging credentials or model prompts. A pre-existing server may have a different proxy environment; use `--standalone`. See `docs/alternate-gateway.md` for limitations.

If a disposable second Tor instance stalls at a bootstrap percentage and times out, Ratriyx refuses to launch the app and cleans up only that temporary Tor instance. A healthy primary Tor route can still be used for diagnostics; inspect temporary Tor notices for slow or blocked circuits rather than assuming the application bypassed the proxy.

## Direct connectivity unavailable

Run `ratriyx run --opencode --mode direct` to clear proxy variables for that child. This does not change the current shell's environment or Windows-wide network settings. A direct IP probe failure is reported separately.

## Strict mode refuses to start

Strict OS-enforced isolation is not implemented. `ratriyx strict check` checks Windows capabilities without enabling firewall filters. `ratriyx run --strict` deliberately refuses and leaves the child unstarted.

## Legacy Privoxy configuration

`run --privoxy`, `ip --privoxy`, `configure`, `restore`, and explicit Privoxy removal remain solely for older installations. These settings are not part of normal setup, doctor, status or embedded Tor launch. Uninstall removal requires ownership checks or explicit additional authorization.
