# Proxy recovery

Recovery returns a machine to a known route. It never guesses. Each step is previewed first and changes only what you approve.

## Principles

1. Classify the observation before acting. A refused connection, a timeout, an `IsTor: false` response, and a provider 429 have different causes and different fixes.
2. Preview with `ratriyx recover --target direct|tor` (dry run is the default). Apply with `--apply --yes` only after reading the plan.
3. Direct recovery never stops Tor. Tor recovery starts only services that are stopped, and only after approval.
4. Ratriyx changes the environment of processes it starts. It cannot change a running application, a PowerShell profile, Zed, or an OpenCode server that was started earlier. Use one `--session` name per terminal so snapshots do not cross.

## Direct target

Use this when you want ordinary networking for new processes, for example after Tor or Privoxy was stopped.

```bash
ratriyx recover --target direct           # preview
eval "$(ratriyx off)"                      # clear proxy variables in this shell, if the plan lists them
ratriyx run --mode direct -- opencode      # start OpenCode with no proxy variables
```

The plan lists proxy variables set in the current shell. Ratriyx does not stop Tor or Privoxy for direct mode.

## Tor target

Use this when you want routed traffic again.

```bash
ratriyx recover --target tor               # preview: which services, which rule, IsTor now
ratriyx recover --target tor --apply --yes # starts only the stopped services listed
sudo ratriyx configure --yes               # only if the plan lists the forwarding rule
ratriyx doctor --mode tor
```

When `IsTor` is true, the plan prints a scoped launch command: `ratriyx run --mode tor -- opencode`. Until then, the command is withheld.

## Error classes

| Observation | Class | Response |
|---|---|---|
| Refused at `127.0.0.1:8118` | Privoxy not listening | Check the service. Offer direct mode or an approved start. |
| Refused at Tor SOCKS port | Tor not listening | Check the Tor service (`tor@default` on Debian/Ubuntu systemd, plain `tor` elsewhere), not the master unit. |
| Timeout | Transport delay | Report the endpoint and time. No retry loop. |
| TLS verification failed | Transport security | Report. Verification is never disabled. |
| HTTP 407 | Proxy authentication | Report. Credentials are not shown. |
| `IsTor: false` | Route not verified | Inspect forwarding. Tor mode fails. |
| HTTP 401 or 403 from a provider | Provider authentication | Report the provider response. |
| HTTP 429 or "Rate limit exceeded" | Provider limit | Report the provider limit. Not a proxy fault. |
| HTTP 5xx from a provider | Upstream | Report. No retry loop. |

## Rate limits

A provider 429 means the provider limited the request. It can depend on your account, key, plan, usage, or time, and a different Tor exit does not change it. Ratriyx never cycles identities, rotates accounts, or retries a rate-limited request to get past the limit. The result is reported as received.

## What recovery cannot change

- System-wide proxy settings and PowerShell profile/machine variables.
- Zed's environment.
- An OpenCode server started before the change. Restart it.
- Applications that ignore proxy variables or set their own proxy.
- DNS that is resolved locally in a direct request.

## Status of this build

Implemented: plan generation, approved service starts, the forwarding rule through `configure`, and the scoped launch command. Not implemented: a provider probe, so provider classes above are reported from observed status codes only, and recovery of a stuck Tor circuit beyond restarting the instance.
