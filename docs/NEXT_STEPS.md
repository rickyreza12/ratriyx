# Ratriyx: what comes next

**Baseline:** v0.4.1 documentation release, published October 28, 2026.
The functional baseline remains v0.4.0.
This is a prioritized engineering roadmap, **not a claim that the listed
features already work**. Work should move to the next milestone only after
its acceptance checks are demonstrated. No release dates are promised.

## Where v0.4 stands

**Delivered**

- Native CLI with the C Tor client and embedded Rust HTTP-to-SOCKS5 frontend
  for `run --mode tor` and `ip`, with an explicit legacy `--privoxy` option.
- Verified per-request Tor checks and `privacy check` warnings; no anonymity
  claims based on exit-IP differences alone.
- Foreground `desktop serve` plus individually approved PowerShell, Zed and
  Windows current-user proxy settings; guarded restoration.
- Windows Documents known-folder lookup for PowerShell 5.1 and 7, including
  OneDrive redirection and conservative migration of earlier managed blocks.
- Read-only `strict check`, experimental Windows WFP and Job Object
  prerequisites, and a **refusing `run --strict` command**.
- Tor `rotate status` and controlled NEWNYM request without any promise of
  new exits or provider-limit changes.

**Still missing:** tested OS-enforced process-tree isolation, comprehensive
Windows desktop settings acceptance, complete Privoxy-free setup, and
end-to-end runtime validation on standalone Linux and macOS.

## P0. Secure the v0.4 release path

1. Keep default-branch source and README aligned with the published crate.
   Validate a clean `cargo install ratriyx --locked` in a disposable
   environment, then confirm the binary reports `0.4.0`.
2. Exercise a fresh Windows PowerShell 5.1 profile and a OneDrive-redirected
   profile, including existing content, migration backups, repeated enable,
   disable, and actual `IsTor=true` checks. Repeat for PowerShell 7.
3. Test Zed JSONC settings insertion/removal and WinINet current-user
   enable/disable on disposable user profiles, including pre-existing proxy,
   PAC, registry changes by a third party, and interrupted operations.
4. Confirm failure behavior when Tor or the foreground desktop proxy stops.
   Proxy-aware clients must not quietly fall back to direct; clearly document
   clients that ignore the proxy altogether.
5. Verify the published package contains required source, licenses and docs,
   but excludes one-off local patches, credentials and machine-specific files.

**Gate:** A second machine can install and remove the release without
corrupting pre-existing user settings. A repeatable test report records
Windows versions, executed checks, and unverified cases.

## P0. Build real strict application isolation

`ratriyx run --strict --mode tor -- PROGRAM` must **continue to refuse**
until all applicable requirements below pass. Do not present WFP
preflight, proxy environment variables or a Job Object alone as enforcement.

1. **Lifecycle and identity:** Start the protected application suspended;
   place it in a no-breakaway process-tree containment mechanism; preserve
   identity across Node, Bun, CMD launchers and child processes. An executable
   path alone is not a reliable identity for one application instance.
2. **Windows network guard:** Use reviewed WFP rules for outbound IPv4 and
   IPv6, TCP and UDP/QUIC, including DNS behavior. Permit only the validated
   local proxy endpoint for the protected tree. Do not accidentally block or
   trust unrelated processes sharing a binary or loopback address.
3. **Crash-safe ownership:** If Ratriyx or Tor fails, protected descendants
   must be terminated or held blocked *before* any firewall rule disappears.
   Remove only Ratriyx-owned rules, recover stale state safely, and preserve
   other firewall policies.
4. **Privilege model:** Explain required elevation or service permissions
   before making changes. Missing permissions must not launch an unguarded
   child or alter the user's broader network configuration.
5. **Adversarial acceptance:** In a disposable Windows VM, run deliberate
   direct IPv4/IPv6 TCP, UDP/QUIC, DNS, inherited-connection, helper-process,
   proxy-crash and parent-crash leak tests. Route-allowed HTTP and HTTPS must
   return `IsTor=true`. Prove cleanup and isolation of unrelated processes.

**Gate:** Strict mode may be enabled **only** on a platform whose independent
end-to-end suite passes. Keep unsupported platforms fail-closed.
See [strict-routing-v0.4.md](strict-routing-v0.4.md) for the full threat model.

## P1. Complete the Privoxy-independent workflow

- Move the remaining `doctor`, `setup`, `env`, `on`, and recovery paths
  toward the embedded proxy where appropriate, without silently changing
  existing installations. Keep the legacy `--privoxy` route as an explicit
  compatibility option during migration.
- Add negative and streaming-protocol tests: malformed HTTP, request bodies,
  chunked transfer, CONNECT teardown, timeouts, cancellation, DNS behavior,
  large payloads, concurrent clients, and controlled resource consumption.
- Decide whether a managed foreground/background proxy service is needed for
  desktop settings. If implemented, design explicit startup, shutdown, health
  checks, local-user permissions, and crash recovery before enabling it.
- Update installation and troubleshooting docs after the dependencies and
  commands actually change.

**Gate:** A fresh system can complete a supported per-process Tor workflow
without installing Privoxy, while existing users can upgrade and roll back.

## P1. Verify Linux and macOS separately

- **Linux:** Evaluate a network namespace plus nftables and a trusted local
  proxy bridge. Test rootless setup feasibility, DNS, IPv6, inherited sockets,
  subprocesses, mount/namespace lifecycle and cleanup.
- **macOS:** Evaluate Network Extension and entitlement/signing constraints
  before promising a system-level guard. Test supported macOS versions and
  package installation explicitly.
- Keep OS-specific acceptance reports. Code compiling on an OS is not
  equivalent to verified application isolation.

**Gate:** Publish support claims only for platform/version combinations with
repeatable live installation and network checks.

## P2. Operability and future evaluation

- Improve clear status reporting for proxy availability, Tor bootstrap,
  settings ownership and active-profile mismatches.
- Add safe local logging and redaction review, with diagnostics that do not
  expose tokens, browser/session identifiers or Tor control credentials.
- Evaluate [Arti](https://gitlab.torproject.org/tpo/core/arti) as a distinct,
  optional Tor transport. Assess compatibility, build size, features,
  licensing and maturity before any backend migration. Arti does not replace
  the OS-level strict guard.
- Build a release checklist for Windows, WSL2, standalone Linux and macOS.
  Attach evidence for both ordinary mode and any enabled strict backend.

## Release checklist

- [ ] README and version history describe the exact published behavior.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --all-targets --locked -- -D warnings` passes.
- [ ] `cargo test --locked` passes, with opt-in live tests reported separately.
- [ ] `cargo publish --dry-run --locked` passes with no unexpected files.
- [ ] Native Windows embedded proxy succeeds with `IsTor=true`.
- [ ] Desktop profile migration, disable/restore, and interruptions have
      written test results. Do not infer coverage from unit tests.
- [ ] Unsupported strict routing continues to fail closed before child launch.
- [ ] Change approval and rollback are exercised without touching unrelated
      user/network settings.

## Out of scope

Ratriyx will not bypass AI-provider HTTP 429/account quotas, impersonate
identities, promise a fresh exit IP for every request, or claim that Tor alone
guarantees anonymity. Circuit separation is a privacy feature, not a quota
reset mechanism.
