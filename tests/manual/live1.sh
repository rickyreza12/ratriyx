#!/bin/bash
# HISTORICAL live test, part 1 (ran 2026-10-15 with approval; do not re-run
# without fresh approval). Services and /etc/privoxy/config. Run as root only.
set -euo pipefail
W=/tmp/ratriyx-live
R=/mnt/e/Projects/NyxRoute/apps/target/release/ratriyx
CFG=/etc/privoxy/config
RULE_RE='^forward-socks5t[[:space:]]+/[[:space:]]+127\.0\.0\.1:9050[[:space:]]+\.[[:space:]]*$'
rm -rf "$W"; mkdir -m 700 "$W"; mkdir -p "$W/home" "$W/cfg" "$W/state"
export HOME="$W/home" XDG_CONFIG_HOME="$W/cfg" XDG_STATE_HOME="$W/state"
UNITS="tor@default privoxy tor"

states() { for u in $UNITS; do echo "$u=$(systemctl is-active "$u")"; done; }
short() { cut -c1-12; }
section() { echo; echo "== $1"; }

section "initial service states"
states | tee "$W/states.before"
ls /etc/privoxy | grep -E '^config\.ratriyx-bak-' > "$W/bak.before" || true

section "backup and rollback preparation"
ORIG_SHA=$(sha256sum "$CFG" | cut -d' ' -f1)
read -r ORIG_MODE ORIG_UID ORIG_GID < <(stat -c '%a %u %g' "$CFG")
echo "original: sha256=$(echo "$ORIG_SHA" | short)... mode=$ORIG_MODE owner=$ORIG_UID:$ORIG_GID"
cp -p "$CFG" "$W/config.orig" || { echo "BACKUP FAILED"; exit 20; }
chmod 600 "$W/config.orig"
[ "$(sha256sum "$W/config.orig" | cut -d' ' -f1)" = "$ORIG_SHA" ] || { echo "BACKUP HASH MISMATCH"; exit 21; }
echo "backup hash verified"

rollback() {
  install -m "$ORIG_MODE" -o "$ORIG_UID" -g "$ORIG_GID" "$W/config.orig" "$1"
}
rollback "$W/scratch" || { echo "ROLLBACK PREP FAILED"; exit 22; }
S_SHA=$(sha256sum "$W/scratch" | cut -d' ' -f1)
read -r S_MODE S_UID S_GID < <(stat -c '%a %u %g' "$W/scratch")
if [ "$S_SHA" != "$ORIG_SHA" ] || [ "$S_MODE" != "$ORIG_MODE" ] || [ "$S_UID:$S_GID" != "$ORIG_UID:$ORIG_GID" ]; then
  echo "ROLLBACK DRY RUN MISMATCH"; exit 23
fi
rm -f "$W/scratch"
echo "rollback rehearsed on a scratch file: hash, mode, owner match"

DONE=0
finalize() {
  [ "$DONE" = 1 ] && return
  DONE=1
  section "finalize: restore config and services"
  rollback "$CFG"
  # Remove only backup files created by this test.
  for f in $(ls /etc/privoxy | grep -E '^config\.ratriyx-bak-'); do
    grep -qxF "$f" "$W/bak.before" || { rm -f "/etc/privoxy/$f"; echo "removed test backup $f"; }
  done
  systemctl restart privoxy
  for u in $UNITS; do
    want=$(grep "^$u=" "$W/states.before" | cut -d= -f2)
    now=$(systemctl is-active "$u")
    if [ "$want" = active ] && [ "$now" != active ]; then systemctl start "$u"; fi
    if [ "$want" != active ] && [ "$now" = active ]; then systemctl stop "$u"; fi
  done
  sleep 3
  F_SHA=$(sha256sum "$CFG" | cut -d' ' -f1)
  read -r F_MODE F_UID F_GID < <(stat -c '%a %u %g' "$CFG")
  echo "restored: sha256=$(echo "$F_SHA" | short)... mode=$F_MODE owner=$F_UID:$F_GID"
  [ "$F_SHA" = "$ORIG_SHA" ] && echo "HASH MATCH: yes" || echo "HASH MATCH: NO"
  [ "$F_MODE:$F_UID:$F_GID" = "$ORIG_MODE:$ORIG_UID:$ORIG_GID" ] && echo "PERMS MATCH: yes" || echo "PERMS MATCH: NO"
  echo "final service states:"; states | tee "$W/states.after"
  diff -q "$W/states.before" "$W/states.after" >/dev/null && echo "STATES MATCH INITIAL: yes" || echo "STATES MATCH INITIAL: NO"
}
trap finalize EXIT

wait_port() { for _ in $(seq 1 30); do ss -ltn | grep -q ":$1 " && return 0; sleep 1; done; return 1; }
wait_route() { for _ in $(seq 1 90); do "$R" status 2>/dev/null | grep -q 'route:.*verified' && return 0; sleep 2; done; return 1; }
brief() { grep -E '^\[(FAIL|WARN)|^summary' ; }

section "config edit: remove the rule, then let ratriyx add it back"
grep -v -E "$RULE_RE" "$CFG" > "$W/config.mod"
removed=$(( $(wc -l < "$CFG") - $(wc -l < "$W/config.mod") ))
echo "rule lines removed in the test copy: $removed"
install -m "$ORIG_MODE" -o "$ORIG_UID" -g "$ORIG_GID" "$W/config.mod" "$CFG"
echo "configure --dry-run:"; "$R" configure --dry-run 2>&1 | cut -c1-110; echo "rc=${PIPESTATUS[0]}"
echo "privoxy --config-test on edited file: rc=$(privoxy --config-test "$CFG" >/dev/null 2>&1; echo $?)"
echo "configure --yes:"; "$R" configure --yes 2>&1 | sed -E 's#(backup at )[^;]*#\1<path>#; s#--file .*#--file <path>#' | cut -c1-140; echo "rc=${PIPESTATUS[0]}"
ls -l /etc/privoxy | grep ratriyx-bak | awk '{print $1, $3, $4, "<backup file>"}'
echo "privoxy --config-test after configure: rc=$(privoxy --config-test "$CFG" >/dev/null 2>&1; echo $?)"
echo "forwarding after configure: $("$R" status | grep 'privoxy forwarding')"
systemctl restart privoxy; wait_port 8118 && echo "privoxy restarted, listening"
echo "doctor --mode tor after restart:"; "$R" doctor --mode tor | brief; echo "rc=${PIPESTATUS[0]}"
echo "restore --yes:"; "$R" restore --yes 2>&1 | sed -E 's#(from )[^ ]*$#\1<path>#' | cut -c1-120; echo "rc=${PIPESTATUS[0]}"
[ "$(sha256sum "$CFG" | cut -d' ' -f1)" = "$(sha256sum "$W/config.mod" | cut -d' ' -f1)" ] && echo "restore returned the pre-configure text: yes" || echo "restore returned the pre-configure text: NO"

section "stopped Privoxy"
rollback "$CFG"; systemctl restart privoxy; wait_port 8118
systemctl stop privoxy; echo "privoxy=$(systemctl is-active privoxy)"
echo "doctor --mode direct:"; "$R" doctor --mode direct | brief; echo "rc=${PIPESTATUS[0]}"
echo "doctor --mode tor:"; "$R" doctor --mode tor | brief; echo "rc=${PIPESTATUS[0]}"
echo "run --mode tor -- true:"; "$R" run --mode tor -- true 2>&1 | cut -c1-120; echo "rc=${PIPESTATUS[0]}"
echo "run --mode direct -- true:"; "$R" run --mode direct -- true 2>&1 | cut -c1-120; echo "rc=${PIPESTATUS[0]}"
systemctl start privoxy; wait_port 8118 && echo "privoxy started"
echo "doctor --mode tor after start:"; "$R" doctor --mode tor | brief; echo "rc=${PIPESTATUS[0]}"

section "stopped Tor instance"
systemctl stop tor@default; echo "tor@default=$(systemctl is-active tor@default)"
echo "doctor --mode direct:"; "$R" doctor --mode direct | brief; echo "rc=${PIPESTATUS[0]}"
echo "doctor --mode tor:"; "$R" doctor --mode tor | brief; echo "rc=${PIPESTATUS[0]}"
echo "run --mode tor -- true:"; "$R" run --mode tor -- true 2>&1 | cut -c1-120; echo "rc=${PIPESTATUS[0]}"
echo "run --mode direct -- true:"; "$R" run --mode direct -- true 2>&1 | cut -c1-120; echo "rc=${PIPESTATUS[0]}"
systemctl start tor@default; wait_route && echo "tor@default started, route verified" || echo "route NOT verified within 180 s"
echo "doctor --mode tor after start:"; "$R" doctor --mode tor | brief; echo "rc=${PIPESTATUS[0]}"

section "OpenCode warnings (no launch expected)"
"$R" doctor --mode tor --app opencode | grep -iE 'opencode' | cut -c1-150
echo "run --opencode --mode tor:"; timeout 20 "$R" run --opencode --mode tor 2>&1 | cut -c1-150 | head -8; echo "rc=${PIPESTATUS[0]}"

section "429 preserved (local mock server only, no real provider)"
if command -v python3 >/dev/null; then
  cat > "$W/mock429.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(429); self.send_header("Content-Length", "10"); self.end_headers(); self.wfile.write(b"rate limit")
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
print(s.server_address[1], flush=True)
s.handle_request()
PY
  python3 "$W/mock429.py" > "$W/mock.port" &
  for _ in 1 2 3 4 5; do [ -s "$W/mock.port" ] && break; sleep 1; done
  P=$(cat "$W/mock.port")
  OUT=$("$R" run --mode direct -- curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/" 2>/dev/null); RC=$?
  echo "child saw HTTP $OUT, ratriyx exit=$RC"
else
  echo "python3 missing: not run"
fi

finalize
