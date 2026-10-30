# Alternate outbound gateways (no VPS Tor or local SOCKS5)

Ratriyx can use a separately operated SOCKS5 endpoint to route proxy-aware
applications through another public IP. This is useful for connectivity
testing, privacy, and selecting a network path. **It does not bypass
OpenCode/provider free-usage limits, account controls, or rate limits.**

## No-VPS option: a second disposable Tor client (Windows)

Ratriyx can start a second local Tor process using the already-installed
managed Tor executable. It does not need a VPS, VPN subscription, extra
download or system-wide proxy changes. The new client has a separate data
directory and loopback SOCKS port, excludes the observed existing Tor exit
address, and compares its verified Tor Project exit IP to both the original
Tor exit and the direct public IP before launching the requested program.

```powershell
cd E:\Projects\NyxRoute\apps
.\target\release\ratriyx.exe gateway tor check
.\target\release\ratriyx.exe gateway tor run --opencode -- --version
.\target\release\ratriyx.exe gateway tor run --opencode -- --standalone
```

### Investigate OpenCode's actual outbound requests

Use the newest built binary (the feature-branch version may differ from a
published or globally installed version). With the app's existing provider
configuration, launch its own private server and enable *metadata-only* tracing:

```powershell
.\target\release\ratriyx.exe gateway tor run --trace-connections --opencode -- --standalone
```

In the OpenCode UI, issue at most one permitted test request with an intended
model. A non-interactive `opencode run --standalone --model PROVIDER/MODEL
"test"` can also be used, but choose the model explicitly to avoid unexpected
charges. Do not run multiple provider requests when a usage limit is exhausted.

`--trace-connections` is off by default and also works with regular `run`
and external `gateway run`, provided Ratriyx owns the embedded proxy.
It is deliberately rejected in `run --mode direct` and `run --privoxy`.
Before launching the child, Ratriyx checks Tor with its *own* requests; those
are **not** counted. While an interactive OpenCode TUI is on screen, trace
events are kept in a bounded in-memory buffer instead of being written to
the shared terminal, which would corrupt the full-screen interface. **Close
OpenCode to display the trace.** Ratriyx then prints entries such as
`CONNECT socks-attempt host=api.example.org port=443`, `socks-connected`,
`CONNECT tunnel-established`, and a summary of accepted clients and successful
or failed SOCKS connections. The buffer retains at most 512 events, reports
omitted events, and continues counting all connections in the summary.

The trace contains no request path, query, headers, API keys, body, prompt or
model response. A hostname may itself be sensitive, so review output before
sharing. If you observe a provider hostname with an established tunnel, that
is evidence the **observed connection** passed through the Ratriyx bridge;
it does not prove every subprocess or request did. An empty trace is
inconclusive when the app has not demonstrably sent a network request.
Read-only Windows process/TCP inspection can provide supporting evidence,
but does not reveal TLS request URLs. `--standalone` avoids reusing a
background OpenCode server whose environment was set before Ratriyx launch.

If OpenCode reports `Free usage limit reached` while a provider CONNECT tunnel
is observed, treat the provider quota response separately from local routing.
Do not retry exhausted free models or rotate accounts to evade provider limits.

**Observed on Windows, 2026-10-31:** One minimal OpenCode `run --standalone`
test using the original managed Tor route produced proxied CONNECT tunnels to
`models.opencode.ai:443` and `opencode.ai:443`, followed by OpenCode's
`Free usage limit reached` response. Other app-phase proxy connections were
also observed. No raw HTTP model request was decrypted, so this establishes
provider-domain connection routing and response correlation, not proof that
every connection or HTTP request from OpenCode was proxied. A separate attempt
on the disposable second Tor route failed to bootstrap beyond 67% in 180 seconds
and correctly refused child launch. The primary Tor route remained functional.

The normal Ratriyx-managed Tor listener must already be running. A fresh
second instance may take time to fetch network state and bootstrap. When
the checking command exits, Ratriyx stops *only* the temporary Tor child
and removes its temporary data directory. The original Tor process remains
unchanged. If the new instance cannot bootstrap, cannot verify `IsTor=true`,
or reports an exit equal to an excluded address, the child application is
not launched. Optional `--different-from IP` also excludes an explicitly
specified prior IP.

**Limit:** This proves the IP of the exact verification request at that
moment, not an immutable external IP for every request. Different Tor
streams may choose other exits, and applications ignoring proxy settings
may connect directly. Selecting a different route cannot refresh or
circumvent a service's free-usage quota.

## Optional external SOCKS5 gateway (SSH / VPS)

## Requirements

- A server/VPS you own or are authorized to use, with a public IPv4/IPv6
  address and SSH access.
- Windows OpenSSH client (`ssh`), or a pre-existing local SOCKS5 listener.
- `curl` and a working direct HTTPS connection for independent IP comparison.

## Start the upstream gateway

In one PowerShell window, start a local SOCKS5 listener whose outbound
connections leave through your remote server:

```powershell
ssh -N -D 127.0.0.1:1080 USER@YOUR_VPS_PUBLIC_IP
```

Keep that terminal running while using the gateway. Replace the username
and server address with **your own authorized SSH access**. Ratriyx does
not install this server or create new public IP allocations.

## Check and launch

In another PowerShell window:

```powershell
cd E:\Projects\NyxRoute\apps
.\target\release\ratriyx.exe gateway check --socks 127.0.0.1:1080
.\target\release\ratriyx.exe gateway run --socks 127.0.0.1:1080 --opencode -- --version
.\target\release\ratriyx.exe gateway run --socks 127.0.0.1:1080 --opencode -- --standalone
```

If you also need to exclude a previously observed Tor exit:

```powershell
.\target\release\ratriyx.exe gateway check --socks 127.0.0.1:1080 --different-from 93.95.227.37
```

Substitute your **current** Tor IP; the example is only a past observation.
Pointing `--socks` to Ratriyx's existing Tor port `127.0.0.1:9050`
only reuses Tor, and is **not** a third gateway. Use your independently
operated SSH tunnel for a genuinely separate public egress.
The gateway fails closed if its public IP matches direct or the excluded IP,
the SOCKS listener is absent, the IP probe fails, or the probe response is
unparseable. No app launches in these cases. This confirms the route used
by the probe, but cannot guarantee that every application connection uses
the proxy, or that a different IP will remain allocated over time.

The child inherits scoped HTTP/HTTPS/ALL_PROXY variables using Ratriyx's
ephemeral embedded Rust HTTP-to-SOCKS bridge. The process is not a VPN;
apps that ignore proxy variables, plugins, raw sockets, and background
OpenCode servers can use other routes. Restart previously running servers
before expecting them to use a new route. The listener owned by Ratriyx
ends when the child exits; the separate SSH tunnel remains your responsibility.

Gateway mode is separate from Tor mode, never checks `IsTor`, and never
tries to retry or modify provider requests. An IP difference is not proof
of anonymity. Do not share SSH secrets or API tokens in logs.
