#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_URL=${BASE_URL:-http://127.0.0.1:3000}
REALM=${REALM:-demo}
SPIN_UP=${SPIN_UP:-0}
SPIN_BUILD=${SPIN_BUILD:-0}
SPIN_STATE_DIR=${SPIN_STATE_DIR:-"$ROOT_DIR/.spin"}
SPIN_MANIFEST=${SPIN_MANIFEST:-"$ROOT_DIR/spin.toml"}
SPIN_LOG=${SPIN_LOG:-"$SPIN_STATE_DIR/logs/spin-identity-provider.log"}

IDP_ALIAS=${IDP_ALIAS:-"idp-$RANDOM"}
IDP_NAME=${IDP_NAME:-"Test IdP $RANDOM"}
IDP_PROVIDER_ID=${IDP_PROVIDER_ID:-"oidc"}
IDP_MAPPER_ID=${IDP_MAPPER_ID:-"idp-mapper-$RANDOM"}

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

step "create identity provider"
create_payload=$(IDP_ALIAS="$IDP_ALIAS" IDP_NAME="$IDP_NAME" IDP_PROVIDER_ID="$IDP_PROVIDER_ID" python3 - <<'PY'
import json
import os

payload = {
  "alias": os.environ["IDP_ALIAS"],
  "displayName": os.environ["IDP_NAME"],
  "providerId": os.environ["IDP_PROVIDER_ID"],
  "enabled": True,
  "config": {"clientId": "demo", "clientSecret": "secret"},
}
print(json.dumps(payload))
PY
)
read -r code out < <(request POST "/admin/realms/$REALM/identity-provider/instances" "$create_payload")
expect_status "$code" "$out" 201
rm -f "$out"

step "list identity providers"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances")
expect_status "$code" "$out" 200
rm -f "$out"

step "get identity provider"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS")
expect_status "$code" "$out" 200
rm -f "$out"

step "update identity provider"
update_payload=$(IDP_NAME="$IDP_NAME" python3 - <<'PY'
import json
import os

payload = {
  "displayName": f"{os.environ.get('IDP_NAME', '')} updated",
  "config": {"clientId": "demo2"},
}
print(json.dumps(payload))
PY
)
read -r code out < <(request PUT "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS" "$update_payload")
expect_status "$code" "$out" 204
rm -f "$out"

step "import identity provider config"
import_payload=$(python3 - <<'PY'
import json

payload = {"clientId": "demo", "clientSecret": "secret"}
print(json.dumps(payload))
PY
)
read -r code out < <(request POST "/admin/realms/$REALM/identity-provider/import-config" "$import_payload")
expect_status "$code" "$out" 200
rm -f "$out"

step "export identity provider"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/export")
expect_status "$code" "$out" 200
rm -f "$out"

step "mapper types"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/mapper-types")
expect_status "$code" "$out" 200
rm -f "$out"

step "create identity provider mapper"
mapper_payload=$(IDP_ALIAS="$IDP_ALIAS" IDP_MAPPER_ID="$IDP_MAPPER_ID" python3 - <<'PY'
import json
import os
import random

payload = {
  "id": os.environ["IDP_MAPPER_ID"],
  "name": f"mapper-{random.randint(1000, 99999)}",
  "identityProviderAlias": os.environ["IDP_ALIAS"],
  "identityProviderMapper": "oidc-user-attribute-idp-mapper",
  "config": {"syncMode": "INHERIT"},
}
print(json.dumps(payload))
PY
)
read -r code out < <(request POST "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/mappers" "$mapper_payload")
expect_status "$code" "$out" 200
IDP_MAPPER_ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$out")
rm -f "$out"

step "list identity provider mappers"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/mappers")
expect_status "$code" "$out" 200
rm -f "$out"

step "get identity provider mapper"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/mappers/$IDP_MAPPER_ID")
expect_status "$code" "$out" 200
rm -f "$out"

step "update identity provider mapper"
mapper_update_payload=$(python3 - <<'PY'
import json

payload = {
  "name": "mapper-updated",
  "identityProviderMapper": "oidc-user-attribute-idp-mapper",
  "config": {"syncMode": "FORCE"},
}
print(json.dumps(payload))
PY
)
read -r code out < <(request PUT "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/mappers/$IDP_MAPPER_ID" "$mapper_update_payload")
expect_status "$code" "$out" 204
rm -f "$out"

step "delete identity provider mapper"
read -r code out < <(request DELETE "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/mappers/$IDP_MAPPER_ID")
expect_status "$code" "$out" 204
rm -f "$out"

step "reload identity provider keys"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/reload-keys")
expect_status "$code" "$out" 200
rm -f "$out"

step "identity provider permissions"
read -r code out < <(request GET "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/management/permissions")
expect_status "$code" "$out" 200
rm -f "$out"

step "update identity provider permissions"
read -r code out < <(request PUT "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS/management/permissions" '{"enabled":true}')
expect_status "$code" "$out" 200
rm -f "$out"

step "delete identity provider"
read -r code out < <(request DELETE "/admin/realms/$REALM/identity-provider/instances/$IDP_ALIAS")
expect_status "$code" "$out" 200
rm -f "$out"

echo "OK"
