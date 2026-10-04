#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: tools/yon-smoke/smoke.sh SESAME_BINARY [FYLO_BINARY]" >&2
  echo "FYLO_BINARY may also come from the environment; ty, curl and jq must be on PATH." >&2
  exit 2
}

fail() {
  echo "FAIL $*" >&2
  exit 1
}

pass() {
  echo "ok   $*"
}

absolute_path() {
  local path=$1
  [ -x "$path" ] || fail "setup: $path is not an executable file"
  echo "$(cd "$(dirname "$path")" && pwd)/$(basename "$path")"
}

require_commands() {
  local name
  for name in "$@"; do
    command -v "$name" >/dev/null || fail "setup: $name is not on PATH"
  done
}

stop_process_from() {
  local pid_file=$1
  local -r attempts=50
  local pid attempt
  [ -f "$pid_file" ] || return 0
  pid=$(cat "$pid_file")
  rm -f "$pid_file"
  kill -TERM "$pid" 2>/dev/null || return 0
  for ((attempt = 0; attempt < attempts; attempt++)); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

stop_everything() {
  local workspace=$1
  stop_process_from "$workspace/writer.pid"
  stop_process_from "$workspace/holder.pid"
  stop_process_from "$workspace/server.pid"
  rm -rf "$workspace"
}

random_password() {
  local file=$1
  local -r random_bytes=32
  head -c "$random_bytes" /dev/urandom | base64 | tr -d '\n=+/' >"$file"
}

create_deployment() {
  local workspace=$1 binary=$2 fylo_binary=$3
  local -r issuer=https://sesame.test
  "$binary" init --deployment "$workspace/deployment" --fylo-binary "$fylo_binary" \
    --issuer "$issuer" >"$workspace/init.json" 2>>"$workspace/engine.log" ||
    fail "setup: sesame init failed (see the engine log)"
  pass "setup: sesame init --issuer $issuer"
}

bootstrap_administrator() {
  local workspace=$1 binary=$2 tenant=$3
  local person="$workspace/people/$tenant-admin"
  "$binary" admin bootstrap --deployment "$workspace/deployment" --name "$tenant" \
    --identifier-namespace email --identifier-value "admin@$tenant.test" \
    >"$person.created" 2>>"$workspace/engine.log" || fail "setup: sesame admin bootstrap $tenant failed"
  jq -r .tenant.tenant_id "$person.created" >"$person.tenant"
  jq -r .administrator.principal_id "$person.created" >"$person.principal"
  echo "admin@$tenant.test" >"$person.identifier"
  pass "setup: sesame admin bootstrap --name $tenant"
}

create_member() {
  local workspace=$1 binary=$2 tenant=$3
  local person="$workspace/people/$tenant-member"
  cp "$workspace/people/$tenant-admin.tenant" "$person.tenant"
  "$binary" principal create --deployment "$workspace/deployment" --tenant-id "$(cat "$person.tenant")" \
    --kind human --identifier-namespace email --identifier-value "member@$tenant.test" \
    >"$person.created" 2>>"$workspace/engine.log" || fail "setup: sesame principal create in $tenant failed"
  jq -r .principal_id "$person.created" >"$person.principal"
  echo "member@$tenant.test" >"$person.identifier"
  pass "setup: sesame principal create member@$tenant.test"
}

set_passwords() {
  local workspace=$1 binary=$2
  local person count=0
  : >"$workspace/password-frames"
  for person in "$workspace"/people/*.principal; do
    person=${person%.principal}
    random_password "$person.password"
    cat "$person.password" >>"$workspace/secrets"
    echo >>"$workspace/secrets"
    jq -cn --arg principal "$(cat "$person.principal")" --rawfile password "$person.password" \
      '{protocol_version: "1", request_id: ("smoke-" + $principal), operation: "authenticator.set_password",
        parameters: {principal_id: $principal, password: $password}}' >>"$workspace/password-frames"
    count=$((count + 1))
  done
  "$binary" exec --loop --deployment "$workspace/deployment" <"$workspace/password-frames" \
    >"$workspace/password-replies" 2>>"$workspace/engine.log" || fail "setup: sesame exec --loop failed"
  [ "$(jq -s '[.[] | select(.ok == true)] | length' "$workspace/password-replies")" = "$count" ] ||
    fail "setup: authenticator.set_password did not succeed for all $count principals"
  pass "setup: sesame exec --loop authenticator.set_password x$count"
}

prepare_project() {
  local workspace=$1 binary=$2 root=$3
  local -r wait_milliseconds=2000
  local project="$workspace/project"
  mkdir "$project"
  cp -R "$root/server" "$root/package.json" "$project/"
  jq --arg binary "$binary" --arg deployment "$workspace/deployment" --argjson wait "$wait_milliseconds" \
    '.sesame = ((.sesame // {}) + {binary: $binary, deployment: $deployment, waitmilliseconds: $wait})' \
    "$root/server/application.json" >"$project/server/application.json"
  pass "setup: project copy in the temporary directory, sesame.waitmilliseconds=$wait_milliseconds"
}

start_server() {
  local workspace=$1 fylo_binary=$2
  local -r ready_seconds=300
  local deadline=$((SECONDS + ready_seconds))
  local url="" ty_binary
  ty_binary=$(command -v ty)
  PATH="$(dirname "$fylo_binary"):$PATH" "$ty_binary" serve --port 0 --no-watch \
    "$workspace/project" >"$workspace/server.log" 2>&1 &
  echo $! >"$workspace/server.pid"
  while [ -z "$url" ]; do
    kill -0 "$(cat "$workspace/server.pid")" 2>/dev/null ||
      fail "server: ty serve exited before it was ready: $(tail -n 5 "$workspace/server.log")"
    [ "$SECONDS" -lt "$deadline" ] || fail "server: ty serve was not ready within ${ready_seconds}s"
    sleep 0.5
    url=$(sed -n 's|^Tachyon server ready at \(http://[^ ]*\)/$|\1|p' "$workspace/server.log" | head -n 1)
  done
  echo "$url" >"$workspace/url"
  pass "server: ty serve ready at $url"
}

call_route() {
  local workspace=$1 method=$2 path=$3 session=$4
  local -r seconds=60
  local arguments=(--silent --show-error --max-time "$seconds" --request "$method"
    --output "$workspace/answer" --dump-header "$workspace/headers" --write-out '%{http_code}')
  if [ "$session" != none ]; then
    arguments+=(--header "@$workspace/people/$session.session")
  fi
  if [ "$method" = POST ]; then
    arguments+=(--header 'Content-Type: application/json' --data-binary "@$workspace/request")
  fi
  curl "${arguments[@]}" "$(cat "$workspace/url")$path" || echo "no-answer"
}

post() {
  local workspace=$1 path=$2 session=$3 body=$4
  printf '%s' "$body" >"$workspace/request"
  call_route "$workspace" POST "$path" "$session"
}

answer_code() {
  local workspace=$1
  jq -r '.code? // empty' "$workspace/answer" 2>/dev/null || true
}

expect_status() {
  local workspace=$1 label=$2 expected=$3 actual=$4
  [ "$actual" = "$expected" ] ||
    fail "$label: expected HTTP $expected, got $actual $(answer_code "$workspace")"
  pass "$label -> $actual"
}

expect_code() {
  local workspace=$1 label=$2 expected=$3
  [ "$(answer_code "$workspace")" = "$expected" ] ||
    fail "$label: expected code $expected, got '$(answer_code "$workspace")'"
  pass "$label -> code $expected"
}

sign_in() {
  local workspace=$1 name=$2
  local person="$workspace/people/$name"
  local status
  status=$(post "$workspace" /api/v1/authn/begin none "$(jq -cn --arg tenant "$(cat "$person.tenant")" \
    --arg identifier "$(cat "$person.identifier")" \
    '{tenant_id: $tenant, identifier_namespace: "email", identifier_value: $identifier}')")
  [ "$status" = 200 ] || fail "sign-in $name: authn/begin answered $status $(answer_code "$workspace")"
  jq -r .transaction_id "$workspace/answer" >"$person.transaction"
  jq -cn --rawfile transaction "$person.transaction" --rawfile password "$person.password" \
    '{transaction_id: ($transaction | rtrimstr("\n")), password: $password}' >"$workspace/request"
  status=$(call_route "$workspace" POST /api/v1/authn/verify-password none)
  [ "$status" = 200 ] || fail "sign-in $name: authn/verify-password answered $status $(answer_code "$workspace")"
  jq -cn --rawfile transaction "$person.transaction" \
    '{transaction_id: ($transaction | rtrimstr("\n"))}' >"$workspace/request"
  status=$(call_route "$workspace" POST /api/v1/authn/complete none)
  [ "$status" = 200 ] || fail "sign-in $name: authn/complete answered $status $(answer_code "$workspace")"
  mv "$workspace/answer" "$person.issued"
  jq -r .session_secret "$person.issued" >>"$workspace/secrets"
  jq -r '"Sesame-Session: \(.session_id):\(.session_secret)"' "$person.issued" >"$person.session"
  pass "sign-in $name: authn/begin, verify-password, complete -> 200"
}

check_public_routes() {
  local workspace=$1
  expect_status "$workspace" "public POST /api/v1/system/ping" 200 \
    "$(post "$workspace" /api/v1/system/ping none '{}')"
  expect_status "$workspace" "public POST /api/v1/token/jwks" 200 \
    "$(post "$workspace" /api/v1/token/jwks none '{}')"
  expect_status "$workspace" "public GET /oidc/openid-configuration" 200 \
    "$(call_route "$workspace" GET /oidc/openid-configuration none)"
  [ "$(jq -r .issuer "$workspace/answer")" = https://sesame.test ] ||
    fail "public GET /oidc/openid-configuration: issuer is not https://sesame.test"
  pass "public GET /oidc/openid-configuration -> issuer https://sesame.test"
}

check_signed_in_routes() {
  local workspace=$1
  local question='{"action":"sesame:administer","resource":"sesame:tenant"}'
  expect_status "$workspace" "signed-in POST /api/v1/authorize/decide without a session" 401 \
    "$(post "$workspace" /api/v1/authorize/decide none "$question")"
  echo "Sesame-Session: not-a-session" >"$workspace/people/malformed.session"
  expect_status "$workspace" "signed-in POST /api/v1/authorize/decide with a malformed session" 401 \
    "$(post "$workspace" /api/v1/authorize/decide malformed "$question")"
  expect_status "$workspace" "signed-in POST /api/v1/authorize/decide as acme member" 200 \
    "$(post "$workspace" /api/v1/authorize/decide acme-member "$question")"
  [ "$(jq -r .decision "$workspace/answer")" = deny ] ||
    fail "signed-in POST /api/v1/authorize/decide as acme member: expected decision deny"
  pass "signed-in POST /api/v1/authorize/decide as acme member -> decision deny"
}

check_administrator_routes() {
  local workspace=$1
  local acme globex
  acme=$(jq -cn --arg tenant "$(cat "$workspace/people/acme-admin.tenant")" '{tenant_id: $tenant}')
  globex=$(jq -cn --arg tenant "$(cat "$workspace/people/globex-admin.tenant")" '{tenant_id: $tenant}')
  expect_status "$workspace" "administrator POST /api/v1/tenant/get without a session" 401 \
    "$(post "$workspace" /api/v1/tenant/get none "$acme")"
  expect_status "$workspace" "administrator POST /api/v1/tenant/get as acme member" 403 \
    "$(post "$workspace" /api/v1/tenant/get acme-member "$acme")"
  expect_status "$workspace" "administrator POST /api/v1/tenant/get as acme admin, own tenant" 200 \
    "$(post "$workspace" /api/v1/tenant/get acme-admin "$acme")"
  expect_status "$workspace" "administrator POST /api/v1/system/metrics as acme admin" 200 \
    "$(post "$workspace" /api/v1/system/metrics acme-admin '{}')"
  expect_status "$workspace" "administrator POST /api/v1/tenant/get as acme admin, globex tenant" 403 \
    "$(post "$workspace" /api/v1/tenant/get acme-admin "$globex")"
  expect_code "$workspace" "administrator POST /api/v1/tenant/get as acme admin, globex tenant" tenant_mismatch
}

check_cross_tenant_reference() {
  local workspace=$1
  local globex foreign_session
  globex=$(jq -cn --arg tenant "$(cat "$workspace/people/globex-admin.tenant")" '{tenant_id: $tenant}')
  foreign_session=$(jq -c '{session_id}' "$workspace/people/globex-admin.issued")
  expect_status "$workspace" "administrator POST /api/v1/session/revoke-by-id as acme admin, globex session" 403 \
    "$(post "$workspace" /api/v1/session/revoke-by-id acme-admin "$foreign_session")"
  expect_code "$workspace" "administrator POST /api/v1/session/revoke-by-id as acme admin, globex session" \
    actor_tenant_mismatch
  expect_status "$workspace" "administrator POST /api/v1/tenant/get as globex admin after the refused revoke" 200 \
    "$(post "$workspace" /api/v1/tenant/get globex-admin "$globex")"
}

check_refused_requests() {
  local workspace=$1
  local smuggled
  smuggled=$(jq -cn --arg tenant "$(cat "$workspace/people/acme-admin.tenant")" \
    '{tenant_id: $tenant, unexpected: "field"}')
  expect_status "$workspace" "administrator POST /api/v1/tenant/get with an undeclared body field" 400 \
    "$(post "$workspace" /api/v1/tenant/get acme-admin "$smuggled")"
  expect_status "$workspace" "unrouted POST /api/v1/federation/login-exchange" 405 \
    "$(post "$workspace" /api/v1/federation/login-exchange none '{}')"
}

hold_deployment() {
  local workspace=$1 binary=$2
  local -r hold_seconds=120
  local -r start_seconds=60
  local deadline=$((SECONDS + start_seconds))
  mkfifo "$workspace/hold"
  (
    printf '%s\n' '{"protocol_version":"1","request_id":"smoke-hold","operation":"system.ping","parameters":{}}'
    exec sleep "$hold_seconds"
  ) >"$workspace/hold" &
  echo $! >"$workspace/writer.pid"
  "$binary" exec --loop --deployment "$workspace/deployment" <"$workspace/hold" \
    >"$workspace/holder.out" 2>>"$workspace/engine.log" &
  echo $! >"$workspace/holder.pid"
  until grep -q '"ok":true' "$workspace/holder.out"; do
    kill -0 "$(cat "$workspace/holder.pid")" 2>/dev/null || fail "busy: the holding sesame exec --loop exited"
    [ "$SECONDS" -lt "$deadline" ] || fail "busy: the holding engine did not answer within ${start_seconds}s"
    sleep 0.2
  done
  pass "busy: a second sesame exec --loop holds the deployment"
}

release_deployment() {
  local workspace=$1
  local -r attempts=100
  local holder attempt
  holder=$(cat "$workspace/holder.pid")
  stop_process_from "$workspace/writer.pid"
  for ((attempt = 0; attempt < attempts; attempt++)); do
    kill -0 "$holder" 2>/dev/null || break
    sleep 0.2
  done
  kill -0 "$holder" 2>/dev/null && fail "busy: the holding engine did not exit after its input closed"
  rm -f "$workspace/holder.pid"
  pass "busy: the holding engine released the deployment"
}

check_busy_engine() {
  local workspace=$1 binary=$2
  hold_deployment "$workspace" "$binary"
  expect_status "$workspace" "busy POST /api/v1/system/ping while the deployment is held" 503 \
    "$(post "$workspace" /api/v1/system/ping none '{}')"
  expect_code "$workspace" "busy POST /api/v1/system/ping while the deployment is held" engine_busy
  grep -qi '^retry-after:' "$workspace/headers" || fail "busy: the 503 answer has no Retry-After header"
  pass "busy POST /api/v1/system/ping while the deployment is held -> Retry-After present"
  release_deployment "$workspace"
  expect_status "$workspace" "public POST /api/v1/system/ping after the deployment is released" 200 \
    "$(post "$workspace" /api/v1/system/ping none '{}')"
}

stop_server() {
  local workspace=$1
  local -r grace_seconds=10
  local deadline=$((SECONDS + grace_seconds))
  stop_process_from "$workspace/server.pid"
  while pgrep -f "$workspace" >/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] || fail "server: processes still run from the temporary directory after ty serve stopped"
    sleep 0.5
  done
  pass "server: ty serve stopped, no engine left running"
}

check_server_log() {
  local workspace=$1
  [ -s "$workspace/secrets" ] || fail "log: no secrets were recorded to look for"
  if grep -v '^$' "$workspace/secrets" | grep -F -q -f - "$workspace/server.log"; then
    fail "log: a password or session secret appears in the ty serve log"
  fi
  pass "log: no password or session secret in the ty serve log"
}

main() {
  local binary fylo_binary root workspace name
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
  require_commands ty curl jq mkfifo pgrep
  binary=$(absolute_path "$1")
  fylo_binary=$(absolute_path "${2:-${FYLO_BINARY:-}}")
  root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
  umask 077
  workspace=$(mktemp -d "${TMPDIR:-/tmp}/sesame-yon-smoke.XXXXXX")
  # shellcheck disable=SC2064
  trap "stop_everything '$workspace'" EXIT
  trap 'exit 130' INT TERM
  mkdir "$workspace/people"
  : >"$workspace/secrets"
  create_deployment "$workspace" "$binary" "$fylo_binary"
  bootstrap_administrator "$workspace" "$binary" acme
  bootstrap_administrator "$workspace" "$binary" globex
  create_member "$workspace" "$binary" acme
  set_passwords "$workspace" "$binary"
  prepare_project "$workspace" "$binary" "$root"
  start_server "$workspace" "$fylo_binary"
  for name in acme-admin globex-admin acme-member; do
    sign_in "$workspace" "$name"
  done
  check_public_routes "$workspace"
  check_signed_in_routes "$workspace"
  check_administrator_routes "$workspace"
  check_cross_tenant_reference "$workspace"
  check_refused_requests "$workspace"
  check_busy_engine "$workspace" "$binary"
  stop_server "$workspace"
  check_server_log "$workspace"
  echo "smoke: all checks passed"
}

main "$@"
