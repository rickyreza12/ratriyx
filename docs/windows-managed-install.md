# Windows managed Tor setup

The 0.4 Windows installer uses the official pinned, checksum-verified Tor Expert Bundle. It stores files in Ratriyx-owned locations under `%LOCALAPPDATA%`, records managed ownership in the Ratriyx state directory, and does not overwrite an existing modified torrc.

| Component | Lifecycle |
|---|---|
| Tor | Reuse a healthy SOCKS5 listener, or start the installed Ratriyx-owned bundle |
| Embedded Rust HTTP proxy | One temporary `127.0.0.1:<ephemeral>` listener for the foreground command |
| curl | Uses the Windows curl.exe for TLS-verified external IP and IsTor checks |
| OpenCode | Discovered on PATH and launched as a separate child |
| Privoxy | Legacy removal or explicit opt-in only; never installed by current setup |

Managed Tor defaults to SOCKS5 `127.0.0.1:9050` and control `127.0.0.1:9051`; changes to an existing managed torrc require manual review. Tor installation requires `ratriyx setup --install --yes`. Routine `ratriyx run --opencode --mode tor` may restart already installed managed Tor and then verifies IsTor through the temporary proxy.

On bootstrap failure, a newly started managed Tor child is stopped and diagnostic logs are retained. Current-user proxy, Wi-Fi, firewall and WinHTTP settings are left untouched by ordinary routing. Legacy Privoxy uninstall never removes unverified unrelated software automatically.
