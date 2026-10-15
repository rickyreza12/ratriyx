# Managed ownership record

Version: 1.

Ratriyx records every dependency file and service it creates so update, rollback, and uninstall touch only Ratriyx-owned items. Pre-existing Tor and Privoxy installations are never recorded and never removed.

## Location

- Linux/macOS: `$XDG_STATE_HOME/ratriyx/managed.toml`, else `~/.local/state/ratriyx/managed.toml`.
- Windows: `%LOCALAPPDATA%\ratriyx\state\managed.toml`.

## Fields

```toml
version = 1
ratriyx_version = "0.2.0"
platform = "windows"      # windows | linux | macos
arch = "x86_64"

[[dependency]]
name = "tor"              # tor | privoxy | curl
source = "winget"         # winget | apt-get | dnf | pacman | brew | official-download
version = "0.4.8.12"
sha256 = "<hex or 'package-manager'>"

[[file]]
path = "/etc/privoxy/ratriyx-managed.conf"
sha256_after = "<hex>"
backup = "/etc/privoxy/ratriyx-managed.conf.ratriyx-bak-<ms>"

[[service]]
name = "RatriyxTor"
unit = "RatriyxTor"        # service name, systemd unit, or launchd label
managed = true
```

## Rules

- Written atomically after each managed change; validated before use.
- Unknown `version` refuses managed operations with a backup-and-recreate path.
- Corrupt file stops managed setup, update, and uninstall; doctor reports it and nothing is claimed.
- Migration: a newer Ratriyx upgrades the record and keeps a dated backup; an older Ratriyx refuses a newer record.
- Uninstall removes only recorded files and services, after separate explicit approval.
