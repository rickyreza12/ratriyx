#!/bin/sh
# Installs Ratriyx from a precompiled GitHub release archive.
# POSIX sh. Overrides for tests: RATRIYX_VERSION, RATRIYX_BASE_URL, RATRIYX_INSTALL_DIR.
# Installs to ~/.local/bin by default; prints PATH guidance, never edits profiles.
set -eu

fail() { echo "ratriyx-install: $1" >&2; exit 1; }

VERSION="${RATRIYX_VERSION:-${1:-}}"
[ -n "$VERSION" ] || fail "set version: install.sh 0.2.0 (or \$RATRIYX_VERSION)"
BASE_URL="${RATRIYX_BASE_URL:-https://github.com/rickyreza12/ratriyx/releases/download/v$VERSION}"
INSTALL_DIR="${RATRIYX_INSTALL_DIR:-$HOME/.local/bin}"

os="${FAKE_UNAME_S:-$(uname -s)}"
arch="${FAKE_UNAME_M:-$(uname -m)}"
case "$os" in
  Linux) os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *) fail "unsupported OS: $os" ;;
esac
case "$arch" in
  x86_64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) fail "unsupported architecture: $arch" ;;
esac
target="$arch-$os"
asset="ratriyx-$VERSION-$target.tar.gz"
url="$BASE_URL/$asset"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
case "$BASE_URL" in
  file://*)
    src=$(printf '%s' "$url" | sed 's|^file://||')
    [ -f "$src" ] || fail "local archive not found: $src"
    cp "$src" "$tmp/$asset"
    ;;
  *)
    command -v curl >/dev/null || fail "curl is required"
    curl -fsSL -o "$tmp/$asset" "$url" || fail "download failed: $url"
    ;;
esac
(cd "$tmp" && curl -fsSL "$url.sha256" -o "$asset.sha256") || fail "checksum download failed"
(cd "$tmp" && sha256sum -c "$asset.sha256") || fail "checksum mismatch for $asset; nothing installed"
mkdir -p "$INSTALL_DIR"
tar -xzf "$tmp/$asset" -C "$tmp"
exe=$(find "$tmp" -name ratriyx -type f | head -1)
[ -n "$exe" ] || fail "archive has no ratriyx binary"
cp "$exe" "$INSTALL_DIR/ratriyx"
chmod +x "$INSTALL_DIR/ratriyx"
echo "installed: $INSTALL_DIR/ratriyx"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) echo "already on PATH: $INSTALL_DIR" ;;
  *) echo "add to PATH: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
