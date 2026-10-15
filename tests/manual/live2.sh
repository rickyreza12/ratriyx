#!/bin/bash
# HISTORICAL live test, part 2 (ran 2026-10-15 with approval for exactly one
# NEWNYM; do not re-run without fresh approval). Run as root only.
set -euo pipefail
W=/tmp/ratriyx-live2
R=/mnt/e/Projects/NyxRoute/apps/target/release/ratriyx
rm -rf "$W"; mkdir -m 700 "$W"; mkdir -p "$W/cfg/ratriyx" "$W/state" "$W/home"
export HOME="$W/home" XDG_CONFIG_HOME="$W/cfg" XDG_STATE_HOME="$W/state"
cat > "$W/cfg/ratriyx/config.toml" <<'EOF'
[tor]
control_enabled = true
control_socket = "/run/tor/control"
EOF
mask() { sed -E 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/<ipv4>/g; s/([0-9a-fA-F]{0,4}:){3,}[0-9a-fA-F:]*/<ipv6>/g'; }
tokens_hash() { grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}|([0-9a-fA-F]{0,4}:){3,}[0-9a-fA-F:]*' | sort | sha256sum | cut -c1-12; }

echo "== before (addresses masked)"
"$R" ip > "$W/ip.before" 2>&1; echo "ip rc=$?"
mask < "$W/ip.before" | cut -c1-120
B=$(tokens_hash < "$W/ip.before")

echo "== rotate (single NEWNYM)"
"$R" rotate --yes 2>&1 | cut -c1-200; echo "rotate rc=${PIPESTATUS[0]}"
sleep 6

echo "== after (addresses masked)"
"$R" ip > "$W/ip.after" 2>&1; echo "ip rc=$?"
mask < "$W/ip.after" | cut -c1-120
A=$(tokens_hash < "$W/ip.after")
[ "$A" = "$B" ] && echo "address set unchanged after NEWNYM" || echo "address set changed after NEWNYM"
echo "== doctor --mode tor"
"$R" doctor --mode tor | grep -E '^\[(FAIL|WARN)|^summary'; echo "rc=${PIPESTATUS[0]}"
rm -rf "$W"; echo "temp config and state removed"
