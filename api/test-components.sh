#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_URL=${BASE_URL:-http://127.0.0.1:3000}
REALM=${REALM:-demo}
SPIN_UP=${SPIN_UP:-0}
SPIN_BUILD=${SPIN_BUILD:-0}
SPIN_STATE_DIR=${SPIN_STATE_DIR:-"$ROOT_DIR/.spin"}
SPIN_MANIFEST=${SPIN_MANIFEST:-"$ROOT_DIR/spin.toml"}
SPIN_LOG=${SPIN_LOG:-"$SPIN_STATE_DIR/logs/spin-components.log"}

COMPONENT_ID=${COMPONENT_ID:-"component-$RANDOM"}
COMPONENT_NAME=${COMPONENT_NAME:-"component-name-$RANDOM"}
PROVIDER_ID=${PROVIDER_ID:-"provider-$RANDOM"}
PROVIDER_TYPE=${PROVIDER_TYPE:-"provider-type-$RANDOM"}
PARENT_ID=${PARENT_ID:-"parent-$RANDOM"}

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

step "create component"
read -r code out < <(request POST "/admin/realms/$REALM/components" '{"id":"'$COMPONENT_ID'","name":"'$COMPONENT_NAME'","providerId":"'$PROVIDER_ID'","providerType":"'$PROVIDER_TYPE'","parentId":"'$PARENT_ID'","subType":"sub","config":{"enabled":["true"],"note":["alpha","beta"]}}')
expect_status "$code" "$out" 200 201
rm -f "$out"

step "list components"
read -r code out < <(request GET "/admin/realms/$REALM/components")
expect_status "$code" "$out" 200
rm -f "$out"

step "filter components by name"
read -r code out < <(request GET "/admin/realms/$REALM/components?name=$COMPONENT_NAME")
expect_status "$code" "$out" 200
rm -f "$out"

step "filter components by parent"
read -r code out < <(request GET "/admin/realms/$REALM/components?parent=$PARENT_ID")
expect_status "$code" "$out" 200
rm -f "$out"

step "filter components by type"
read -r code out < <(request GET "/admin/realms/$REALM/components?type=$PROVIDER_TYPE")
expect_status "$code" "$out" 200
rm -f "$out"

step "get component"
read -r code out < <(request GET "/admin/realms/$REALM/components/$COMPONENT_ID")
expect_status "$code" "$out" 200
rm -f "$out"

step "update component"
read -r code out < <(request PUT "/admin/realms/$REALM/components/$COMPONENT_ID" '{"name":"'$COMPONENT_NAME'-updated","config":{"enabled":["false"],"note":["gamma"]}}')
expect_status "$code" "$out" 200
rm -f "$out"

step "list sub-component types"
read -r code out < <(request GET "/admin/realms/$REALM/components/$COMPONENT_ID/sub-component-types")
expect_status "$code" "$out" 200
rm -f "$out"

step "delete component"
read -r code out < <(request DELETE "/admin/realms/$REALM/components/$COMPONENT_ID")
expect_status "$code" "$out" 204
rm -f "$out"

step "get deleted component"
read -r code out < <(request GET "/admin/realms/$REALM/components/$COMPONENT_ID")
expect_status "$code" "$out" 404
rm -f "$out"

echo "OK"
