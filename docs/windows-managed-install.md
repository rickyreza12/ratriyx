# Windows managed-install strategy (M001, M002)

Evidence date: 2026-10-15. Read-only WinGet searches plus the official Tor Project download page. Nothing installed.

## Trusted source per dependency

| Dependency | Strategy | Trust evidence |
|---|---|---|
| Tor | Official Tor Expert Bundle stable tarball from `dist.torproject.org` (e.g. `torbrowser/15.0.25/tor-expert-bundle-windows-x86_64-15.0.25.tar.gz`) plus its `.asc` signature. No WinGet daemon package exists (`Tor Expert Bundle` search: none; only `TorProject.TorBrowser` browser bundle). | torproject.org publisher, per-release `.asc` signatures. Pin exact version + checksum at implementation time; never float. |
| Privoxy | `Privoxy.Privoxy` 4.1.0 via WinGet. | Publisher `Privoxy Developers`, installer URL on `privoxy.org` mirror, SHA-256 pinned in the WinGet manifest (`88bc92e3…`). |
| curl | Built-in `C:\Windows\system32\curl.exe` first (this machine: 8.21.0, Schannel). Fallback `cURL.cURL` via WinGet. | OS component; fallback publisher `curl` (Daniel Stenberg). Never use PowerShell's `curl` alias. |
| OpenCode | `SST.opencode` via WinGet (this index: 1.18.34). | Publisher `SST`, support at `sst.dev` / `sst/opencode` issues. Managed setup does not install OpenCode; it only detects and launches it. |

MVP blocker rule passes: no unofficial binary is substituted for any dependency.

## Managed Windows layout (M002)

| Purpose | Path |
|---|---|
| Ratriyx binary | `%LOCALAPPDATA%\Programs\Ratriyx\ratriyx.exe` |
| Managed Tor (expert bundle extract) | `%LOCALAPPDATA%\Programs\Ratriyx\deps\tor\` |
| Managed Tor data / cookie / log | `%LOCALAPPDATA%\Programs\Ratriyx\deps\tor\Data\`, `control_auth_cookie`, `tor.log` |
| Managed torrc | `%LOCALAPPDATA%\Programs\Ratriyx\deps\tor\torrc` |
| Managed Privoxy config | `%LOCALAPPDATA%\Programs\Ratriyx\deps\privoxy.conf` |
| Ratriyx config | `%LOCALAPPDATA%\ratriyx\config.toml` |
| Ownership record | `%LOCALAPPDATA%\ratriyx\state\managed.toml` |

Ports: Tor SOCKS `127.0.0.1:9050`, control `127.0.0.1:9051`, Privoxy `127.0.0.1:8118`, all loopback-only.
Ownership: a healthy existing Tor/Privoxy/curl is reused and stays user-owned; only files Ratriyx creates are recorded. Collision: an occupied port or an existing file at a managed path stops setup with the exact conflict; never overwrite.
