#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_URL=${BASE_URL:-http://127.0.0.1:3000}
REALM=${REALM:-demo}
SPIN_UP=${SPIN_UP:-0}
SPIN_BUILD=${SPIN_BUILD:-0}
SPIN_STATE_DIR=${SPIN_STATE_DIR:-"$ROOT_DIR/.spin"}
SPIN_MANIFEST=${SPIN_MANIFEST:-"$ROOT_DIR/spin.toml"}
SPIN_LOG=${SPIN_LOG:-"$SPIN_STATE_DIR/logs/spin-client-scopes.log"}

SCOPE_ID=${SCOPE_ID:-"scope-$RANDOM"}
SCOPE_NAME=${SCOPE_NAME:-"scope-name-$RANDOM"}
SCOPE_NAME_UPDATED=${SCOPE_NAME_UPDATED:-"scope-name-updated-$RANDOM"}
MAPPER_ID=${MAPPER_ID:-"mapper-$RANDOM"}
MAPPER_ID_2=${MAPPER_ID_2:-"mapper-$RANDOM-$RANDOM"}
TEMPLATE_ID=${TEMPLATE_ID:-"template-$RANDOM"}
TEMPLATE_NAME=${TEMPLATE_NAME:-"template-name-$RANDOM"}
TEMPLATE_MAPPER_ID=${TEMPLATE_MAPPER_ID:-"template-mapper-$RANDOM"}

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

step "create client scope"
read -r code out < <(request POST "/admin/realms/$REALM/client-scopes" '{"id":"'$SCOPE_ID'","name":"'$SCOPE_NAME'","protocol":"openid-connect","attributes":{"display.on.consent.screen":"true"}}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "list client scopes"
read -r code out < <(request GET "/admin/realms/$REALM/client-scopes")
expect_status "$code" "$out" 200
rm -f "$out"

step "get client scope"
read -r code out < <(request GET "/admin/realms/$REALM/client-scopes/$SCOPE_ID")
expect_status "$code" "$out" 200
rm -f "$out"

step "update client scope"
read -r code out < <(request PUT "/admin/realms/$REALM/client-scopes/$SCOPE_ID" '{"name":"'$SCOPE_NAME_UPDATED'","protocol":"openid-connect","attributes":{"include.in.token.scope":"true"}}')
expect_status "$code" "$out" 204
rm -f "$out"

step "create protocol mapper"
read -r code out < <(request POST "/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models" '{"id":"'$MAPPER_ID'","name":"test-mapper","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","consentRequired":false,"config":{"user.attribute":"email","claim.name":"email"}}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "list protocol mappers"
read -r code out < <(request GET "/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models")
expect_status "$code" "$out" 200
rm -f "$out"

step "get protocol mapper"
read -r code out < <(request GET "/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models/$MAPPER_ID")
expect_status "$code" "$out" 200
rm -f "$out"

step "update protocol mapper"
read -r code out < <(request PUT "/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models/$MAPPER_ID" '{"id":"'$MAPPER_ID'","name":"test-mapper-updated","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","consentRequired":true,"config":{"user.attribute":"email","claim.name":"email"}}')
expect_status "$code" "$out" 204
rm -f "$out"

step "get protocol mappers by protocol"
read -r code out < <(request GET "/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/protocol/openid-connect")
expect_status "$code" "$out" 200
rm -f "$out"

step "add protocol mappers"
read -r code out < <(request POST "/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/add-models" '[{"id":"'$MAPPER_ID_2'","name":"test-mapper-2","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","consentRequired":false,"config":{"user.attribute":"preferred_username","claim.name":"preferred_username"}}]')
expect_status "$code" "$out" 204
rm -f "$out"

step "delete protocol mapper"
read -r code out < <(request DELETE "/admin/realms/$REALM/client-scopes/$SCOPE_ID/protocol-mappers/models/$MAPPER_ID")
expect_status "$code" "$out" 204
rm -f "$out"

step "delete client scope"
read -r code out < <(request DELETE "/admin/realms/$REALM/client-scopes/$SCOPE_ID")
expect_status "$code" "$out" 204
rm -f "$out"

step "verify client scope deleted"
read -r code out < <(request GET "/admin/realms/$REALM/client-scopes/$SCOPE_ID")
expect_status "$code" "$out" 404
rm -f "$out"

step "create client template"
read -r code out < <(request POST "/admin/realms/$REALM/client-templates" '{"id":"'$TEMPLATE_ID'","name":"'$TEMPLATE_NAME'","protocol":"openid-connect"}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "create template protocol mapper"
read -r code out < <(request POST "/admin/realms/$REALM/client-templates/$TEMPLATE_ID/protocol-mappers/models" '{"id":"'$TEMPLATE_MAPPER_ID'","name":"template-mapper","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","consentRequired":false,"config":{"user.attribute":"email","claim.name":"email"}}')
expect_status "$code" "$out" 201 409
rm -f "$out"

step "delete client template"
read -r code out < <(request DELETE "/admin/realms/$REALM/client-templates/$TEMPLATE_ID")
expect_status "$code" "$out" 204
rm -f "$out"

echo "OK"
