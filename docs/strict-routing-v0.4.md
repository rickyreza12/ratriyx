# Ratriyx v0.4: strict application routing and proxy migration

Status: **design plus a fail-closed CLI foundation, NOT live network isolation.**
The current CLI accepts `ratriyx run --strict --mode tor -- ...` but **refuses to
launch** on every OS until a tested enforcement backend exists. Ordinary
`ratriyx run --mode tor -- ...` remains available with its existing limitations.

## Separate concerns

1. **Transport:** C Tor today, optional embedded Arti later.
2. **Proxy frontend:** The embedded Rust HTTP/1.1 forwarding proxy with CONNECT
   is now the default for `run --mode tor` and `ip`. It forwards hostnames
   via SOCKS5 to C Tor. Privoxy remains an optional legacy frontend and is
   still used by portions of the managed setup and diagnostics.
3. **Network enforcement:** OS-level isolation of all traffic from the protected
   application and descendants. Independent of the selected proxy and Tor backend.
4. **Circuit rotation:** optional Tor NEWNYM control. Independent from enforcement;
   rotation does not promise a new exit address, break existing connections,
   change an application's login identity or reset a provider quota.

### Proxy backend comparison

| Component | Embedded HTTP-to-SOCKS + C Tor | Embedded HTTP + Arti |
|---|---|---|
| Privoxy process/WinGet dependency | eliminated | eliminated |
| Separate Tor executable | remains (managed, verified download) | eliminated |
| Tor implementation | mature C Tor | Arti Rust client |
| Build complexity | low to medium | high, larger dependency surface |
| Circuit controls | existing C Tor protocol | Arti APIs differ |
| DNS for application-proxied hostnames | SOCKS5 hostname field | Tor client handles destination |
| Application traffic enforcement | separate OS guard required | separate OS guard required |

Arti also implements experimental HTTP CONNECT support; audit it before
duplicating features. Raw HTTP forwarding still needs explicit support.
Do not expose a proxy on a non-loopback listening address by default.
Neither design is a transparent VPN.

## Strict threat model

Protected: one explicitly launched application and **all** of its runtime
subprocesses; includes Windows npm CMD/PowerShell shims that may launch Node/Bun.
Assume application code may ignore HTTP_PROXY, launch plugins, send raw TCP,
perform local DNS lookup, use UDP/QUIC, use IPv6 or reuse an existing socket.

Protection requirements:
- Install platform enforcement **before** child execution (avoid launch race).
- Bind enforcement to an unforgeable process identity plus descendant tracking,
  not just a filename, PID checked once, or environment variable.
- Permit protected processes to contact only the designated local proxy endpoint.
  An arbitrary loopback service is not automatically trusted; a SOCKS and HTTP
  endpoint must be owned and validated.
- Block all other outbound IPv4/IPv6 TCP, UDP, ICMP and DNS for protected processes;
  block or deliberately handle inherited sockets and established connections.
- Permit the **separate trusted Tor process** to reach guards/relays without
  granting protected application traffic a direct escape route.
- Validate Tor bootstrap, proxy forwarding and IsTor after enforcement is active.
  IP-change alone is not verification.
- Never silently downgrade strict to proxy-only; policy backend failure, guard
  loss, Tor/proxy failure, untrusted helper process, or incomplete process-tree
  coverage must stop protected requests.
- Keep policy during child shutdown; inspect termination, reparented children,
  background servers and helper launches. Warn/refuse when strict coverage is
  uncertain.
- Persist ownership of created OS rules with crash-safe recovery; remove only
  Ratriyx-owned entries, and never edit unrelated firewall rules.
- Surface enforcement evidence: activated guard ID, process coverage, socket
  denial counts, IPv4/IPv6, DNS, test traffic, cleanup and any untested paths.

**Do not claim absolute prevention of all leaks** without adversarial end-to-end
tests; already-running application servers, hardware/software outside OS policy,
local IPC paths and user-supplied network tunnels expand the threat model.

## Native Windows WFP foundation (development branch)

The Windows-only module now uses windows-sys for direct WFP bindings.
The read-only CLI preflight can be run with:

```powershell
ratriyx strict check
```

It opens a dynamic WFP engine session and immediately closes it. This adds
**zero firewall rules**, requires no Tor restart, and does not claim protected
traffic. A successful result means the WFP engine is reachable only; it does
not prove sufficient firewall permissions or an active kill switch.

The WFP module also compiles an **internal, deliberately uncalled lab-only**
transactional rule installer. Its proposed rule shape for an isolated executable
identity is:

- ALE_AUTH_CONNECT_V4: permit TCP to 127.0.0.1:8118 at higher weight.
- ALE_AUTH_CONNECT_V4: block other outgoing connections from that app.
- ALE_AUTH_CONNECT_V6: block all outgoing IPv6 from that app until an
  explicitly configured IPv6 proxy exists.
- Filters live in a dynamic session and disappear when it closes.
- Failed transactions abort; unrelated firewall rules are not removed.

This is NOT a sufficient application protection mechanism. In particular
WFP ALE_APP_ID targets **all** instances of an executable path and cannot
automatically follow Node/Bun subprocesses. Separate Windows DNS services,
already-established connections and the OS firewall's own arbitration further
require validation. No code path currently installs these filters, and the
strict runner still fails closed.

A Windows Job Object preflight also creates an **empty, temporary kernel job**
with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and immediately destroys it. No child
is assigned and no application is killed. This proves the OS supports the
lifecycle primitive, **not** that an OpenCode process tree is contained.

The eventual strict launcher must create the child in a suspended state,
assign it to a no-breakaway job before resuming it, and ensure every helper
remains inside that job. Job membership does not itself identify traffic
for ALE_APP_ID WFP filters.

**Critical crash invariant:** a dynamic WFP session removes its block filters
if Ratriyx crashes. If protected children survive, they can start connecting
directly once the policy disappears. The child job therefore must be coupled
to an always-alive enforcement supervisor (or a persistent fail-safe service)
and child termination must be proven before any rule teardown. Closing a
kill-on-close job handle is a useful safety mechanism but **by itself does not
prove that no timing gap exists** between WFP filter removal and process death.

**Next gate:** isolated process-tree identity, suspended/atomic launch,
privilege model, verified enforcement of direct TCP, UDP/QUIC, local DNS,
IPv6 and child processes. Only test filter installation on an isolated
disposable VM and a dedicated test executable after explicit approval.

## Platform paths and privilege impact

| Platform | Candidate guard | Gaps to solve before enabling |
|---|---|---|
| Windows | Windows Filtering Platform (ALE, IPv4 + IPv6), protected process tree | Atomic suspended launch, Node/Bun child tracking, WFP privileges, rule cleanup |
| Linux | Network namespace + nftables and a trusted local proxy or socket bridge | Non-root setup, DNS and loopback boundary, inherited sockets, namespace lifecycle |
| macOS | Network Extension / platform firewall enforcement | Entitlements, signing, permissions, child tracking, rollback |

Do NOT install a global firewall rule automatically. Require explicit scoped
approval after an impact preview; test in an isolated machine first. The
application must never start under the strict label before rules are verified.

## Acceptance tests (must pass before lifting the gate)

1. HTTP/HTTPS via proxy succeeds; destination confirms IsTor=true.
2. Direct IPv4 and IPv6 TCP attempts from application are denied.
3. Direct UDP/QUIC and DNS lookups are denied; proxied hostnames use Tor.
4. Application child (including npm shim, Node/Bun, plugins) cannot connect direct.
5. Tor/proxy process termination fails closed; no direct fallback.
6. Parent crash and normal shutdown preserve safety until child exits, then remove
   only owned rules. Stale rules are safely recoverable.
7. Non-elevated run reports missing privileges without launching child.
8. Existing user firewall rules, network interfaces and unrelated processes
   remain unchanged.
9. Native Windows and supported Linux/macOS runners have integration tests.
10. Exit IP is verified per path; no promise that all circuits use the same IP.

## Development sequence

1. **Done:** CLI accepts `--strict` and disallows `direct` and
   `--allow-unverified`; missing backend returns exit code 3 before launch.
2. Windows: design WFP lease ownership, safe suspended process launch,
   subprocess tracking and a minimal isolated test harness; require review.
3. Windows: implement and acceptance-test the WFP guard, scoped rule cleanup,
   process coverage and recovery; only then enable strict operation.
4. Linux/macOS: separate OS backends with their own acceptance gates.
5. **Done for `run` and `ip`:** embedded Rust HTTP-to-SOCKS5 is the default;
   retain C Tor and legacy Privoxy compatibility while expanding HTTP/CONNECT
   acceptance and removing remaining setup dependencies.
6. Evaluate Arti integration independently; no dependency on strict readiness.

## Not in scope

- Evading model-provider quotas, paywalls or account-based restrictions.
- Automatic Tor exit cycling, provider retry on HTTP 429 or identity spoofing.
- Calling an environment proxy a VPN.
