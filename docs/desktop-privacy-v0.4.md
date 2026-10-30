# v0.4 desktop proxy and privacy controls

## Privacy and limitations (README items 1 and 4)

`ratriyx privacy check` runs a verified HTTPS `IsTor` request through the
embedded Rust proxy and reports separate warnings for accounts/cookies, traffic
outside proxy-aware applications, DNS/UDP/IPv6, and provider quotas. It cannot
certify anonymity, hide identity voluntarily sent to services, or isolate all
processes without an OS-level guard. `ratriyx run --strict` still refuses.

`ratriyx rotate status` prints whether Tor control is configured and the
remaining local cooldown. `ratriyx rotate --yes` requests `NEWNYM` through
authenticated C Tor control; post-rotation verification uses the embedded
proxy. Tor can rate-limit signals and existing streams continue on established
circuits. There is no automatic 429 retry or quota reset.

## Opt-in desktop integration (README item 2)

### 1. Keep a foreground proxy running in Terminal A

```powershell
ratriyx desktop serve --port 8119
```

This binds `127.0.0.1:8119` only, checks `IsTor=true` through it and
stays in the foreground. Port 8119 avoids the legacy Privoxy port 8118.
If Tor/proxy is unavailable when starting, no settings are modified.
Do not close this terminal while desktop integrations are enabled.

### 2. Enable only the integrations you want in Terminal B

```powershell
ratriyx desktop on --target powershell --yes  # Windows PowerShell 5.1
ratriyx desktop on --target pwsh --yes        # PowerShell 7+
ratriyx desktop on --target zed --yes         # %APPDATA%/Zed/settings.json
ratriyx desktop on --target windows --yes     # Current-user WinINet proxy
```

Each change is opt-in and checks the live proxy before modifying settings.
PowerShell adds a marked block that checks the proxy port in new terminals.
On Windows, PowerShell 5.1 and PowerShell 7 profiles are located using the
real Documents known-folder path (including OneDrive redirection), not by
assuming `USERPROFILE\Documents`. A repeated `desktop on --target powershell
--yes` migrates the old Ratriyx block from the obsolete path if it exists.
It makes non-overwriting `.ratriyx-before-migration.bak` copies of the
affected profiles before editing and refuses blocks with unexpected changes.
After migration, restart Windows PowerShell 5.1 or dot-source `$PROFILE`.
When port 8119 is temporarily down, the profile still sets proxy variables
and shows a warning; clients that honor these settings fail instead of
silently connecting directly. Applications that ignore proxies remain outside
Ratriyx's protection.
Zed inserts a marked JSONC `proxy` setting, preserving unrelated settings
and refusing to overwrite an existing proxy. Windows updates the **current
user** WinINet registry values, preserving the old values in
`%LOCALAPPDATA%/ratriyx/state/desktop-wininet.snapshot`.
It refuses existing enabled proxies or automatic proxy configuration.
No WinHTTP machine-wide setting is modified, and network requests from apps
ignoring these settings are not forced through Tor.

### 3. Restore before stopping Terminal A

```powershell
ratriyx desktop off --target windows --yes
ratriyx desktop off --target zed --yes
ratriyx desktop off --target pwsh --yes
ratriyx desktop off --target powershell --yes
```

Restore only the targets that were enabled. The Windows restore refuses if
somebody changed the system proxy externally; do not overwrite that change
without review. Restart Zed and new PowerShell terminals for changes to
take effect. Closing Terminal A without restoring can leave a stale proxy,
so use `desktop off` to recover. `ratriyx desktop serve` does not enable
system-wide filtering or stop unrelated processes.

The release gate for claiming strict routing remains Windows WFP process-tree
isolation, direct IPv4/IPv6, DNS and UDP leak tests, firewall lifecycle,
and validation across supported platforms.
