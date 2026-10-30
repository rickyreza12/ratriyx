# Embedded HTTP-to-SOCKS5 frontend (v0.4 path)

This is the default for `ratriyx run --mode tor`, `ratriyx ip`, `ratriyx status`
and Tor-mode `ratriyx doctor`. The newer Tor-only managed setup and recovery
also use the embedded proxy, without a Privoxy installation. Use `--privoxy`
on `run` or `ip` only to select an existing legacy proxy.
It is not an OS-enforced strict network guard or a transparent VPN.

## Try it without changing your current installation

```powershell
cargo build --release --locked
.\target\release\ratriyx.exe run --mode tor -- opencode --standalone
.\target\release\ratriyx.exe ip
```

Replace `opencode --standalone` with another program as needed. This path
launches a temporary HTTP proxy on `127.0.0.1` with an ephemeral port, then
sets the child's HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY values to that port.
SOCKS5 communication goes only to the configured loopback Tor SOCKS listener
(default `127.0.0.1:9050`). Hostnames are sent to SOCKS5 as names, not
resolved through the local DNS resolver. The Tor check via
`https://check.torproject.org/api/ip` must report `IsTor=true` before
the child starts; otherwise it is refused.

For compatibility, `run --embedded-proxy` is still accepted. To use the old
Privoxy route, specify `run --privoxy --mode tor -- ...` or `ip --privoxy`.
`--allow-unverified` is only available with explicit `--privoxy`; strict
mode continues to refuse regardless of backend.

The listener stops when Ratriyx exits. It leaves the existing Privoxy
listener/configuration untouched. No firewall, Tor control settings, global
proxy environment, or service installation is modified.

## Current supported traffic

- HTTP/1.0 and HTTP/1.1 absolute-form requests through SOCKS5, including
  ordinary GET and POST with a single Content-Length field.
- HTTPS via CONNECT tunnel with full duplex byte forwarding.
- SOCKS5 IPv4/IPv6 literals and hostname-based targets.
- Hop-by-hop HTTP headers stripped for ordinary HTTP forwarding.
- Bounded request headers (32 KiB), 64 concurrent clients, and timeouts.
- Upstream errors refuse with 502; no direct TCP fallback exists in the proxy.

## Current limitations

- Chunked **request** transfer encoding, streaming request bodies without
  Content-Length, HTTP Upgrade, HTTP/2 proxy protocol, and proxy authentication
  are not implemented. Unhandled upload forms are rejected rather than routed
  directly. CONNECT can tunnel HTTPS protocols (including HTTP/2 inside TLS).
- Idle CONNECT sessions can time out after 120 seconds. Revisit for long-lived
  OpenCode streams and WebSocket connections.
- Proxy environment variables cannot force application plugins or subprocesses
  to use the proxy; direct IP, DNS, UDP, and IPv6 escapes are possible without
  a future OS-level guard. `--strict` still deliberately refuses to launch.
- `env` and `on` refuse Tor mode because a detached shell snippet cannot own
  and shut down the temporary proxy. Direct mode remains available.
- The embedded proxy has unit tests with a local synthetic SOCKS5 server.
  Real Tor/OpenCode smoke tests passed on one Windows machine; a fresh Tor-only
  installation and adversarial leak tests remain separate release gates.

Existing Privoxy installations are left untouched. Explicit legacy flags and
separately guarded uninstall remain available. Ratriyx cannot reset provider
quotas or guarantee application-wide network isolation.
