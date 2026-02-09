#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_URL=${BASE_URL:-http://127.0.0.1:3000}
REALM=${REALM:-demo}
SPIN_UP=${SPIN_UP:-0}
SPIN_BUILD=${SPIN_BUILD:-0}
SPIN_STATE_DIR=${SPIN_STATE_DIR:-"$ROOT_DIR/.spin"}
SPIN_MANIFEST=${SPIN_MANIFEST:-"$ROOT_DIR/spin.toml"}
SPIN_LOG=${SPIN_LOG:-"$SPIN_STATE_DIR/logs/spin-clients.log"}

CLIENT_UUID=${CLIENT_UUID:-"client-uuid-$RANDOM"}
CLIENT_ID=${CLIENT_ID:-"client-$RANDOM"}
CLIENT_ID_DUP=${CLIENT_ID_DUP:-"client-$RANDOM"}

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

expect_status() {
  local code=$1
  local out=$2
  shift 2
  local ok=0
  for expected in "$@"; do
    if [[ "$code" == "$expected" ]]; then
      ok=1
      break
    fi
  done
  if [[ "$ok" != "1" ]]; then
    cat "$out" >&2
    echo "unexpected status: $code (expected: $*)" >&2
    exit 1
  fi
}

step() {
  echo "==> $1"
}

if [[ "$SPIN_UP" == "1" ]]; then
  if [[ "$SPIN_BUILD" == "1" ]]; then
    (cd "$ROOT_DIR/api" && cargo build --target wasm32-wasip2 --release)
    if [[ -d "$ROOT_DIR/db/init" ]]; then
      (cd "$ROOT_DIR/db/init" && cargo build --target wasm32-wasip2 --release)
    fi
  fi
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

step "ensure realm exists"
read -r code out < <(request POST /admin/realms '{"realm":"'$REALM'","enabled":true}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "create client"
read -r code out < <(request POST "/admin/realms/$REALM/clients" '{"id":"'$CLIENT_UUID'","clientId":"'$CLIENT_ID'","name":"Test Client","protocol":"openid-connect","enabled":true,"redirectUris":["http://localhost/callback"],"webOrigins":["http://localhost"],"attributes":{"foo":"bar"}}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "create duplicate clientId"
read -r code out < <(request POST "/admin/realms/$REALM/clients" '{"id":"client-dup-'$RANDOM'","clientId":"'$CLIENT_ID'","protocol":"openid-connect"}')
expect_status "$code" "$out" 409
rm -f "$out"

step "list clients"
read -r code out < <(request GET "/admin/realms/$REALM/clients")
expect_status "$code" "$out" 200
rm -f "$out"

step "get client"
read -r code out < <(request GET "/admin/realms/$REALM/clients/$CLIENT_UUID")
expect_status "$code" "$out" 200
rm -f "$out"

step "update client"
read -r code out < <(request PUT "/admin/realms/$REALM/clients/$CLIENT_UUID" '{"name":"Updated Client","redirectUris":["http://localhost/updated"],"attributes":{"foo":"baz"}}')
expect_status "$code" "$out" 204
rm -f "$out"

step "delete client"
read -r code out < <(request DELETE "/admin/realms/$REALM/clients/$CLIENT_UUID")
expect_status "$code" "$out" 204
rm -f "$out"

step "get deleted client"
read -r code out < <(request GET "/admin/realms/$REALM/clients/$CLIENT_UUID")
expect_status "$code" "$out" 404
rm -f "$out"

step "delete missing client"
read -r code out < <(request DELETE "/admin/realms/$REALM/clients/$CLIENT_UUID")
expect_status "$code" "$out" 404
rm -f "$out"

step "create clients-initial-access"
read -r code out < <(request POST "/admin/realms/$REALM/clients-initial-access" '{"count":2,"expiration":0}')
expect_status "$code" "$out" 201
TOKEN_ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$out")
rm -f "$out"

step "list clients-initial-access"
read -r code out < <(request GET "/admin/realms/$REALM/clients-initial-access")
expect_status "$code" "$out" 200
rm -f "$out"

step "delete clients-initial-access"
read -r code out < <(request DELETE "/admin/realms/$REALM/clients-initial-access/$TOKEN_ID")
expect_status "$code" "$out" 204
rm -f "$out"

step "get client types"
read -r code out < <(request GET "/admin/realms/$REALM/client-types")
expect_status "$code" "$out" 200
rm -f "$out"

step "update client types"
read -r code out < <(request PUT "/admin/realms/$REALM/client-types" '{}')
expect_status "$code" "$out" 204
rm -f "$out"

step "get client policies"
read -r code out < <(request GET "/admin/realms/$REALM/client-policies/policies")
expect_status "$code" "$out" 200
rm -f "$out"

step "update client policies"
read -r code out < <(request PUT "/admin/realms/$REALM/client-policies/policies" '{}')
expect_status "$code" "$out" 200
rm -f "$out"

step "get client profiles"
read -r code out < <(request GET "/admin/realms/$REALM/client-policies/profiles")
expect_status "$code" "$out" 200
rm -f "$out"

step "update client profiles"
read -r code out < <(request PUT "/admin/realms/$REALM/client-policies/profiles" '{}')
expect_status "$code" "$out" 200
rm -f "$out"

step "get client registration policy providers"
read -r code out < <(request GET "/admin/realms/$REALM/client-registration-policy/providers")
expect_status "$code" "$out" 200
rm -f "$out"

step "get client session stats"
read -r code out < <(request GET "/admin/realms/$REALM/client-session-stats")
expect_status "$code" "$out" 200
rm -f "$out"

step "convert client description"
read -r code out < <(request POST "/admin/realms/$REALM/client-description-converter" '"dummy"')
expect_status "$code" "$out" 200
rm -f "$out"

echo "OK"
