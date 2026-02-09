#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_URL=${BASE_URL:-http://127.0.0.1:3000}
REALM=${REALM:-demo}
SPIN_UP=${SPIN_UP:-0}
SPIN_STATE_DIR=${SPIN_STATE_DIR:-"$ROOT_DIR/.spin"}
SPIN_MANIFEST=${SPIN_MANIFEST:-"$ROOT_DIR/spin.toml"}
SPIN_LOG=${SPIN_LOG:-"$SPIN_STATE_DIR/logs/spin-auth-api.log"}

FLOW_ALIAS=${FLOW_ALIAS:-"auth-flow-$RANDOM"}
FLOW_ID=${FLOW_ID:-"$FLOW_ALIAS"}
EXEC_ID=${EXEC_ID:-"exec-$RANDOM-$RANDOM"}
CONFIG_ID=${CONFIG_ID:-"config-$RANDOM-$RANDOM"}

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

step "list authenticator providers"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/authenticator-providers")
expect_status "$code" "$out" 200
rm -f "$out"

step "list client authenticator providers"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/client-authenticator-providers")
expect_status "$code" "$out" 200
rm -f "$out"

step "list form action providers"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/form-action-providers")
expect_status "$code" "$out" 200
rm -f "$out"

step "list form providers"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/form-providers")
expect_status "$code" "$out" 200
rm -f "$out"

step "list unregistered required actions"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/unregistered-required-actions")
expect_status "$code" "$out" 200
rm -f "$out"

step "list required actions"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/required-actions")
expect_status "$code" "$out" 200
rm -f "$out"

step "missing required action returns 404"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/required-actions/missing-action")
expect_status "$code" "$out" 404
rm -f "$out"

step "missing required action config returns 404"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/required-actions/missing-action/config")
expect_status "$code" "$out" 404
rm -f "$out"

step "missing required action config description returns 404"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/required-actions/missing-action/config-description")
expect_status "$code" "$out" 404
rm -f "$out"

step "missing required action priority returns 404"
read -r code out < <(request POST "/admin/realms/$REALM/authentication/required-actions/missing-action/raise-priority")
expect_status "$code" "$out" 404
rm -f "$out"

step "create auth flow"
read -r code out < <(request POST "/admin/realms/$REALM/authentication/flows" '{"id":"'$FLOW_ID'","alias":"'$FLOW_ALIAS'","providerId":"basic-flow","topLevel":true,"builtIn":false}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "create auth execution"
read -r code out < <(request POST "/admin/realms/$REALM/authentication/executions" '{"id":"'$EXEC_ID'","flowId":"'$FLOW_ID'","authenticator":"test-auth","requirement":"REQUIRED","priority":0}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "get auth execution"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/executions/$EXEC_ID")
expect_status "$code" "$out" 200
rm -f "$out"

step "raise execution priority"
read -r code out < <(request POST "/admin/realms/$REALM/authentication/executions/$EXEC_ID/raise-priority")
expect_status "$code" "$out" 204
rm -f "$out"

step "lower execution priority"
read -r code out < <(request POST "/admin/realms/$REALM/authentication/executions/$EXEC_ID/lower-priority")
expect_status "$code" "$out" 204
rm -f "$out"

step "create execution config"
read -r code out < <(request POST "/admin/realms/$REALM/authentication/executions/$EXEC_ID/config" '{"id":"'$CONFIG_ID'","alias":"cfg-alias","config":{"foo":"bar"}}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "get execution config"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/executions/$EXEC_ID/config")
expect_status "$code" "$out" 200
rm -f "$out"

step "get execution config by id"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/executions/$EXEC_ID/config/$CONFIG_ID")
expect_status "$code" "$out" 200
rm -f "$out"

step "get missing execution config by id"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/executions/$EXEC_ID/config/missing-config")
expect_status "$code" "$out" 404
rm -f "$out"

step "delete auth execution"
read -r code out < <(request DELETE "/admin/realms/$REALM/authentication/executions/$EXEC_ID")
expect_status "$code" "$out" 204
rm -f "$out"

step "verify execution deleted"
read -r code out < <(request GET "/admin/realms/$REALM/authentication/executions/$EXEC_ID")
expect_status "$code" "$out" 404
rm -f "$out"

echo "OK"
