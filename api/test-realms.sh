#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_URL=${BASE_URL:-http://127.0.0.1:3000}
REALM=${REALM:-demo}
SPIN_UP=${SPIN_UP:-0}
SPIN_STATE_DIR=${SPIN_STATE_DIR:-"$ROOT_DIR/.spin"}
SPIN_MANIFEST=${SPIN_MANIFEST:-"$ROOT_DIR/spin.toml"}
SPIN_LOG=${SPIN_LOG:-"$SPIN_STATE_DIR/logs/spin-admin-api.log"}

request() {
  local method=$1
  local path=$2
  local data=${3-}
  local out
  out=$(mktemp)
  local code
  if [[ -n "$data" ]]; then
    code=$(curl -sS -o "$out" -w "%{http_code}" -X "$method" \
      -H "content-type: application/json" \
      --data "$data" \
      "$BASE_URL$path")
  else
    code=$(curl -sS -o "$out" -w "%{http_code}" -X "$method" "$BASE_URL$path")
  fi
  echo "$code" "$out"
}

step() {
  echo "==> $1"
}

if [[ "$SPIN_UP" == "1" ]]; then
  mkdir -p "$(dirname "$SPIN_LOG")"
  spin up -f "$SPIN_MANIFEST" --state-dir "$SPIN_STATE_DIR" --listen 127.0.0.1:3000 >"$SPIN_LOG" 2>&1 &
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
    status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/admin/realms" || true)
    if [[ "$status" != "000" ]]; then
      ready=1
      break
    fi
    sleep 0.2
  done

  if [[ "$ready" != "1" ]]; then
    echo "spin did not become ready; see $SPIN_LOG" >&2
    exit 1
  fi
fi

step "create realm"
read -r code out < <(request POST /admin/realms '{"realm":"'$REALM'","enabled":true,"attributes":{"ui":"alpha"},"supportedLocales":["en","ja"],"smtpServer":{"host":"smtp.example","port":"25"},"localizationTexts":{"en":{"welcome":"hi"}}}')
if [[ "$code" != "201" && "$code" != "409" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
rm -f "$out"

step "list realms"
read -r code out < <(request GET /admin/realms)
if [[ "$code" != "200" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
cat "$out"
rm -f "$out"

step "merge update attributes only"
read -r code out < <(request PUT "/admin/realms/$REALM" '{"attributes":{"ui":"beta"}}')
if [[ "$code" != "204" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
rm -f "$out"

step "verify merge keeps locales"
read -r code out < <(request GET "/admin/realms/$REALM")
if [[ "$code" != "200" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
if ! grep -q '"supportedLocales"' "$out" || ! grep -q '"en"' "$out"; then
  cat "$out" >&2
  echo "merge verification failed" >&2
  exit 1
fi
cat "$out"
rm -f "$out"

step "merge update smtpServer only"
read -r code out < <(request PUT "/admin/realms/$REALM" '{"smtpServer":{"host":"smtp.changed","port":"2525"}}')
if [[ "$code" != "204" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
rm -f "$out"

step "verify smtp merge keeps locales and localization"
read -r code out < <(request GET "/admin/realms/$REALM")
if [[ "$code" != "200" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
if ! grep -q '"supportedLocales"' "$out" || ! grep -q '"en"' "$out"; then
  cat "$out" >&2
  echo "merge verification failed" >&2
  exit 1
fi
if ! grep -q '"localizationTexts"' "$out" || ! grep -q '"welcome"' "$out"; then
  cat "$out" >&2
  echo "merge verification failed" >&2
  exit 1
fi
if ! grep -q '"smtpServer"' "$out" || ! grep -q 'smtp.changed' "$out"; then
  cat "$out" >&2
  echo "merge verification failed" >&2
  exit 1
fi
cat "$out"
rm -f "$out"

step "merge update localization only"
read -r code out < <(request PUT "/admin/realms/$REALM" '{"localizationTexts":{"en":{"welcome":"updated"}}}')
if [[ "$code" != "204" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
rm -f "$out"

step "verify localization merge keeps smtp"
read -r code out < <(request GET "/admin/realms/$REALM")
if [[ "$code" != "200" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
if ! grep -q '"smtpServer"' "$out" || ! grep -q 'smtp.changed' "$out"; then
  cat "$out" >&2
  echo "merge verification failed" >&2
  exit 1
fi
if ! grep -q '"localizationTexts"' "$out" || ! grep -q 'updated' "$out"; then
  cat "$out" >&2
  echo "merge verification failed" >&2
  exit 1
fi
cat "$out"
rm -f "$out"

step "delete realm"
read -r code out < <(request DELETE "/admin/realms/$REALM")
if [[ "$code" != "204" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
rm -f "$out"

step "verify realm deleted"
read -r code out < <(request GET "/admin/realms/$REALM")
if [[ "$code" != "404" ]]; then
  cat "$out" >&2
  echo "unexpected status: $code" >&2
  exit 1
fi
rm -f "$out"

echo "OK"
