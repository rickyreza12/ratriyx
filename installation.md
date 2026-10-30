# Install and run Ratriyx 0.4.0

Tor is required for Tor routing. Ratriyx contains its own Rust HTTP-to-SOCKS5 proxy, so Privoxy is optional legacy software.

## Windows

Build from the canonical checkout:

```powershell
cd E:/Projects/NyxRoute/apps
cargo fmt --all -- --check
cargo check --all-targets
cargo test
cargo build --release
./target/release/ratriyx.exe --version
./target/release/ratriyx.exe setup --dry-run
```

Preview and explicitly approve an initial managed Tor installation:

```powershell
./target/release/ratriyx.exe setup --install
./target/release/ratriyx.exe setup --install --yes
```

Windows setup uses a checksum-pinned Tor Expert Bundle, stores owned Tor files under the user profile, waits for SOCKS5 and bootstrap, and verifies IsTor through a temporary embedded proxy. It does not install Privoxy or change system proxy settings. A later Tor-mode `run` can start previously installed managed Tor without downloading new software.

## Linux, WSL2 and macOS

Install Tor and curl with the host package manager. Example on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install tor curl
cargo build --release
./target/release/ratriyx setup --dry-run
./target/release/ratriyx doctor --mode tor
```

Approved Linux setup can start an existing Tor service on supported hosts. macOS automatic service startup needs separate validation. A Privoxy rule is not needed by the normal launch path.

## Verify and launch

```powershell
./target/release/ratriyx.exe status
./target/release/ratriyx.exe ip
./target/release/ratriyx.exe doctor --mode tor --app opencode
./target/release/ratriyx.exe run --opencode --mode tor
./target/release/ratriyx.exe run --opencode --mode direct
```

Tor mode verifies IsTor=true through the exact temporary proxy before launching. Direct mode clears inherited proxy environment variables in the child. Existing OpenCode background processes must be restarted when changing routes.

Free usage limits and `provider.quota` are provider responses rather than routing errors. Ratriyx does not bypass or reset account quotas.

## Cleanup and legacy migration

Each Tor-mode launch owns its proxy listener until the routed child exits. Tor-mode `env` and `on` refuse because shell snippets cannot keep the temporary proxy running. Legacy `--privoxy`, `configure`, `restore`, and guarded uninstall remain opt-in. Strict routing is unavailable pending an OS-level guard.

See [docs/troubleshooting.md](docs/troubleshooting.md) and [docs/security.md](docs/security.md).