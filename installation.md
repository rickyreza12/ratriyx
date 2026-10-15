# Installation

Ratriyx needs Tor, Privoxy, `curl`, and a Rust toolchain. Ratriyx does not install any of them. Each step below is yours to run and review.

## Ubuntu on WSL2 (tested target)

### 1. Check the platform

```bash
uname -r              # should contain "microsoft"
. /etc/os-release && echo "$ID $VERSION_ID"   # ubuntu 24.04
```

Ratriyx refuses to run anywhere else and exits with code 3.

## 2. Install Tor and Privoxy (you run this)

```bash
sudo apt-get update
sudo apt-get install tor privoxy curl
```

Make Privoxy forward to Tor. Ratriyx can add this rule for you later (see step 5), or you can add it yourself:

```conf
forward-socks5t / 127.0.0.1:9050 .
```

Check that Tor is running, and that the instance (not just the master unit) is active:

```bash
systemctl is-active tor@default
systemctl is-active privoxy
```

## 3. Install Rust

Install Rust with `rustup` from <https://rustup.rs>, then confirm:

```bash
rustc --version && cargo --version
```

## 4. Build Ratriyx

```bash
cd /path/to/NyxRoute/apps
cargo build --release
sudo install -m 0755 target/release/ratriyx /usr/local/bin/ratriyx   # optional
```

Check the build the same way the project does:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## 5. First run

```bash
ratriyx --help
ratriyx setup --dry-run        # read-only summary of what is installed and missing
ratriyx doctor --mode direct   # direct network and local state only
ratriyx doctor --mode tor      # the full routed check
ratriyx ip                     # direct address and proxied Tor check, reported separately
```

If `doctor --mode tor` reports the forwarding rule missing:

```bash
ratriyx configure --dry-run    # shows the rule and the file it would change
sudo ratriyx configure --yes   # privileged: appends the rule after a backup
```

Ratriyx writes a backup named `/etc/privoxy/config.ratriyx-bak-<ms>` and a record beside it. Undo with `sudo ratriyx restore --yes`.

## 6. Optional configuration

Ratriyx reads `~/.config/ratriyx/config.toml` if it exists. Missing means defaults. Example:

```toml
[proxy]
host = "127.0.0.1"
port = 8118

[privoxy]
# config_path = "/etc/privoxy/config"   # default on Linux; set per platform

[tor]
socks_host = "127.0.0.1"
socks_port = 9050
control_enabled = false
# control_host = "127.0.0.1"   # optional; defaults to socks_host when empty
control_port = 9051
cookie_path = "/run/tor/control.authcookie"
# Optional Unix socket instead of the TCP control port, for example Debian's "/run/tor/control".
# control_socket = "/run/tor/control"

[runner]
default_target = "opencode"
mode = "per_process"
require_tor = true

[security]
localhost_only = true
verify_tls = true
```

`rotate` needs `control_enabled = true`, and on Debian and Ubuntu the control socket and cookie belong to the `debian-tor` group, so the user must be able to read them. Only loopback addresses are accepted. `verify_tls = false`, `localhost_only = false`, and `require_tor = false` are refused on purpose.

## 7. Run a program through the route

```bash
ratriyx run --mode tor -- curl https://example.com        # refuses if the route is not verified
ratriyx run --mode direct -- opencode                      # direct, proxy variables removed for the child
ratriyx run --opencode                                     # OpenCode through the same runner
```

Shell variables for the current shell (you evaluate the output yourself):

```bash
eval "$(ratriyx on)"     # Tor mode for this shell
eval "$(ratriyx off)"    # restore what was there before
```

PowerShell is supported through process-scoped `$env:` assignments printed by `ratriyx env --shell powershell`. Ratriyx never edits profiles or machine-level variables. Native Windows setup uses `scripts/windows/`; see below.

## Plain Linux (systemd; acceptance NOT VERIFIED)

Same steps as WSL2, except:

- Any Linux distribution with systemd works through the same units. `tor@default` is probed first, then plain `tor`.
- Without systemd, service checks report unknown instead of failing.
- Config and state follow XDG (`~/.config/ratriyx`, `~/.local/state/ratriyx`).
- Set `privoxy.config_path` in `config.toml` if your Privoxy config lives outside `/etc/privoxy/config`.

## Native Windows with PowerShell 5.1 (runtime NOT VERIFIED)

1. Install Tor, Privoxy, and `curl.exe` natively, for example under `$env:LOCALAPPDATA\Programs\TorPrivoxy` with `torrc`, `TorData\`, and `privoxy.conf` there. Tor needs `CookieAuthentication 1` and a loopback ControlPort (default `127.0.0.1:9051`).
2. Build or copy the `ratriyx.exe` binary, then in Windows PowerShell:
   ```powershell
   Set-Location $env:LOCALAPPDATA\Programs\TorPrivoxy
   .\Start-Proxy.ps1
   .\Status-Proxy.ps1
   ```
3. Point Ratriyx at the Windows paths in `%LOCALAPPDATA%\ratriyx\config.toml`:
   ```toml
   [proxy]
   host = "127.0.0.1"
   port = 8118

   [privoxy]
   config_path = "C:\\Users\\you\\AppData\\Local\\Programs\\TorPrivoxy\\privoxy.conf"
   ```
   (TOML needs doubled backslashes.)
4. Use process-scoped variables only: `ratriyx env --shell powershell` prints `$env:` assignments for you to evaluate. Fresh terminals do not inherit them; Zed terminals inherit from Zed's own environment, so restart Zed or set them there.
5. Rotate with `.\Rotate-Tor.ps1`. It sends one NEWNYM per 10 seconds at most and never promises a new exit.
6. Stop with `.\Stop-Proxy.ps1`, which stops only the tracked PIDs.

Always use `curl.exe`, never the `curl` alias, for curl syntax. Never print the cookie.

## macOS with Homebrew (runtime NOT VERIFIED)

1. `brew install tor privoxy` (both Intel and Apple Silicon prefixes are discovered).
2. Start Tor and Privoxy with `brew services` or foreground processes, bound to loopback.
3. If your Privoxy config is not at `/opt/homebrew/etc/privoxy/config`, set `privoxy.config_path` in `~/.config/ratriyx/config.toml`.
4. Service control beyond `status` uses `launchctl` where available; otherwise manage the services yourself and use `doctor` to verify.

## Uninstall

```bash
ratriyx uninstall          # lists the files Ratriyx owns, changes nothing
ratriyx uninstall --yes    # removes only those files
```

Tor and Privoxy are never removed by Ratriyx. Remove them with `sudo apt-get remove tor privoxy` if you want.
