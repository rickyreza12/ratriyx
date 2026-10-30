# Alternate outbound gateway (local SOCKS5 + owned VPS)

Ratriyx can use a separately operated SOCKS5 endpoint to route proxy-aware
applications through another public IP. This is useful for connectivity
testing, privacy, and selecting a network path. **It does not bypass
OpenCode/provider free-usage limits, account controls, or rate limits.**

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
