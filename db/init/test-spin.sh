#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
APP_DIR="$ROOT_DIR/db/init"
MANIFEST="$APP_DIR/spin.toml"
SPIN_LOG="$ROOT_DIR/.spin/logs/spin-db-init.log"

mkdir -p "$(dirname "$SPIN_LOG")"
cd "$APP_DIR"

cargo build --target wasm32-wasip2 --release

cd "$ROOT_DIR"

spin up -f "$MANIFEST" --state-dir "$ROOT_DIR/.spin" --listen 127.0.0.1:3000 >"$SPIN_LOG" 2>&1 &
SPIN_PID=$!

cleanup() {
  if kill -0 "$SPIN_PID" 2>/dev/null; then
    kill "$SPIN_PID" 2>/dev/null || true
    wait "$SPIN_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 50); do
  status=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/db/init || true)
  if [[ "$status" == "405" || "$status" == "200" ]]; then
    ready=1
    break
  fi
  sleep 0.2
done

if [[ "$ready" != "1" ]]; then
  echo "spin did not become ready; see $SPIN_LOG" >&2
  exit 1
fi

init_response=$(curl -s -X POST http://127.0.0.1:3000/db/init)
echo "init response: $init_response"

DB_FILE="$ROOT_DIR/.spin/sqlite/default.db"
if [[ ! -f "$DB_FILE" ]]; then
  DB_FILE=$(find "$ROOT_DIR" -type f -name "*.db" | head -n 1 || true)
fi

if [[ -z "$DB_FILE" || ! -f "$DB_FILE" ]]; then
  echo "sqlite database file not found" >&2
  exit 1
fi

python3 - <<PY
import sqlite3
import sys

path = r"$DB_FILE"
try:
    conn = sqlite3.connect(path)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kc_schema_version'")
    row = cur.fetchone()
    if not row:
        raise SystemExit("kc_schema_version table not found")
finally:
    conn.close()

print(f"sqlite database created: {path}")
PY
