#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/supervisor-middleware-egress-usage"
RUN_TEST_SUITE=0
PRINT_CONFIG=0

usage() {
  cat <<USAGE
usage: $0 [--test-suite|--test|--print-config]

Without flags, starts a local Docker-driver gateway, the egress-usage TCP
middleware, and a package proxy stand-in, creates an example sandbox, and keeps
the stack running. Limits come from the config in policy.yaml.

Options:
  --test-suite, --test  Run the burst scenarios, then stop.
  --print-config        Print the generated gateway config, then stop.

Environment:
  EGRESS_USAGE_SMOKE_HOST        Non-loopback host address reachable from
                                 supervisor containers.
  EGRESS_USAGE_SUPERVISOR_IMAGE  Use a prebuilt supervisor image and skip the
                                 gateway, CLI, and image builds.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --test-suite | --test) RUN_TEST_SUITE=1; shift ;;
    --print-config) PRINT_CONFIG=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

detect_service_host() {
  if [[ -n "${EGRESS_USAGE_SMOKE_HOST:-}" ]]; then
    printf '%s\n' "$EGRESS_USAGE_SMOKE_HOST"
    return
  fi
  ip route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }'
}

SERVICE_HOST="$(detect_service_host)"
[[ -n "$SERVICE_HOST" ]] || { echo "set EGRESS_USAGE_SMOKE_HOST" >&2; exit 1; }

SMOKE_TMP_DIR="$(mktemp -d)"
LOG_DIR="$SMOKE_TMP_DIR/logs"
JWT_DIR="$SMOKE_TMP_DIR/jwt"
GATEWAY_CONFIG="$SMOKE_TMP_DIR/gateway.toml"
SETUP_LOG="$LOG_DIR/setup.log"
GATEWAY_LOG="$LOG_DIR/gateway.log"
MIDDLEWARE_LOG="$LOG_DIR/middleware.log"
UPSTREAM_LOG="$LOG_DIR/upstream.log"
SANDBOX_LOG="$LOG_DIR/sandbox.log"
RUN_ID="egress-usage-smoke-$$-$RANDOM"
SUPERVISOR_IMAGE="${EGRESS_USAGE_SUPERVISOR_IMAGE:-localhost/openshell-egress-usage/supervisor:$RUN_ID}"
SANDBOX_NAME="eu-$$-$RANDOM"
SANDBOX_CREATED=0
# The scenarios need curl and python3 in the sandbox.
SANDBOX_IMAGE="${EGRESS_USAGE_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"

mkdir -p "$LOG_DIR"

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$SANDBOX_CREATED" -eq 1 && -n "${CLI+x}" ]]; then
    "${CLI[@]}" sandbox delete "$SANDBOX_NAME" >>"$SETUP_LOG" 2>&1 || true
  fi
  for pid in "${GATEWAY_PID:-}" "${MIDDLEWARE_PID:-}" "${UPSTREAM_PID:-}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ "$status" -eq 0 ]]; then
    rm -rf "$SMOKE_TMP_DIR"
  else
    echo "logs retained in $LOG_DIR" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

choose_port_block() {
  local start offset ok
  for _ in {1..200}; do
    start=$((20000 + RANDOM % 20000))
    ok=1
    for ((offset = 0; offset < 3; offset++)); do
      if (exec 3<>"/dev/tcp/127.0.0.1/$((start + offset))") 2>/dev/null; then
        ok=0
        break
      fi
    done
    if [[ "$ok" == "1" ]]; then
      printf '%s\n' "$start"
      return
    fi
  done
  echo "failed to find free local ports" >&2
  exit 1
}

PORT_BASE="$(choose_port_block)"
MIDDLEWARE_PORT="$PORT_BASE"
GATEWAY_PORT="$((PORT_BASE + 1))"
HEALTH_PORT="$((PORT_BASE + 2))"
GATEWAY_ENDPOINT="http://127.0.0.1:$GATEWAY_PORT"

write_gateway_config() {
  cat >"$GATEWAY_CONFIG" <<TOML
[openshell]
version = 2

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT_DIR/signing.pem"
public_key_path = "$JWT_DIR/public.pem"
kid_path = "$JWT_DIR/kid"
gateway_id = "$RUN_ID"

[[openshell.supervisor.middleware]]
name = "egress-usage-example"
grpc_endpoint = "http://$SERVICE_HOST:$MIDDLEWARE_PORT"
allow_insecure_transport = true
# Required by the gateway config schema; unused by TCP bindings.
max_payload_bytes = 65536
timeout = "500ms"

[openshell.drivers.docker]
supervisor_image = "$SUPERVISOR_IMAGE"
# A unique label keeps other local gateways from reconciling these containers.
sandbox_label = "$RUN_ID"
TOML
}

write_gateway_config
if [[ "$PRINT_CONFIG" -eq 1 ]]; then
  cat "$GATEWAY_CONFIG"
  exit 0
fi

dump_logs() {
  local path
  for path in "$SETUP_LOG" "$GATEWAY_LOG" "$MIDDLEWARE_LOG" "$UPSTREAM_LOG" "$SANDBOX_LOG"; do
    printf '\n--- %s ---\n' "$path" >&2
    tail -n 100 "$path" >&2 2>/dev/null || printf '(missing)\n' >&2
  done
}

capture_logs() {
  local container_id
  container_id="$(docker ps -aq --format '{{.ID}} {{.Names}}' | awk -v name="--$SANDBOX_NAME-" 'index($2, name) && $2 ~ /-supervisor$/ { print $1; exit }')"
  if [[ -n "$container_id" ]]; then
    docker logs "$container_id" >"$SANDBOX_LOG" 2>&1 || true
  fi
}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  capture_logs
  dump_logs
  exit 1
}

run_setup_step() {
  local label="$1"
  shift
  printf 'INFO %s\n' "$label"
  printf '\n== %s ==\n' "$label" >>"$SETUP_LOG"
  "$@" >>"$SETUP_LOG" 2>&1 || fail "$label"
}

cargo_target_dir() {
  cargo metadata --format-version=1 --no-deps --manifest-path "$1" | jq -er '.target_directory'
}

generate_gateway_jwt_bundle() {
  mkdir -p "$JWT_DIR"
  openssl genpkey -algorithm ed25519 -out "$JWT_DIR/signing.pem" >/dev/null 2>&1
  openssl pkey -in "$JWT_DIR/signing.pem" -pubout -out "$JWT_DIR/public.pem" >/dev/null 2>&1
  printf '%s\n' "$RUN_ID" >"$JWT_DIR/kid"
}

start_upstream() {
  printf 'INFO starting package proxy stand-in on host.openshell.internal\n'
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=host.openshell.internal" \
    -addext "subjectAltName=DNS:host.openshell.internal" \
    -keyout "$SMOKE_TMP_DIR/key.pem" -out "$SMOKE_TMP_DIR/cert.pem" >/dev/null 2>&1
  UPSTREAM_TLS_CERT="$SMOKE_TMP_DIR/cert.pem" UPSTREAM_TLS_KEY="$SMOKE_TMP_DIR/key.pem" \
    python3 -u "$EXAMPLE_DIR/upstream.py" >"$UPSTREAM_LOG" 2>&1 &
  UPSTREAM_PID=$!
  for _ in {1..30}; do
    kill -0 "$UPSTREAM_PID" 2>/dev/null || fail "upstream starts (ports 47080, 47081, 47443, 47900)"
    if grep -q 'upstream ready' "$UPSTREAM_LOG"; then
      return
    fi
    sleep 1
  done
  fail "upstream is ready"
}

start_middleware() {
  printf 'INFO starting egress-usage service at %s:%s\n' "$SERVICE_HOST" "$MIDDLEWARE_PORT"
  "$MIDDLEWARE_BIN" \
    --bind "0.0.0.0:$MIDDLEWARE_PORT" \
    >"$MIDDLEWARE_LOG" 2>&1 &
  MIDDLEWARE_PID=$!
  for _ in {1..60}; do
    kill -0 "$MIDDLEWARE_PID" 2>/dev/null || fail "egress-usage service starts"
    if (exec 3<>"/dev/tcp/$SERVICE_HOST/$MIDDLEWARE_PORT") 2>/dev/null; then
      return
    fi
    sleep 1
  done
  fail "egress-usage service is reachable"
}

start_gateway() {
  printf 'INFO starting gateway\n'
  env -u OPENSHELL_DRIVERS -u OPENSHELL_COMPUTE_DRIVER "$GATEWAY_BIN" \
    --compute-driver docker \
    --config "$GATEWAY_CONFIG" \
    --bind-address 127.0.0.1 \
    --port "$GATEWAY_PORT" \
    --health-port "$HEALTH_PORT" \
    --metrics-port 0 \
    --log-level "${EGRESS_USAGE_SMOKE_LOG_LEVEL:-info}" \
    --disable-tls \
    --db-url "sqlite://$SMOKE_TMP_DIR/gateway.db" >"$GATEWAY_LOG" 2>&1 &
  GATEWAY_PID=$!
  for _ in {1..60}; do
    kill -0 "$GATEWAY_PID" 2>/dev/null || fail "gateway starts with egress-usage"
    if curl -fsS "http://127.0.0.1:$HEALTH_PORT/healthz" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  fail "gateway starts with egress-usage"
}

create_sandbox() {
  CLI=(env -u OPENSHELL_SANDBOX_POLICY "$CLI_BIN" --gateway-endpoint "$GATEWAY_ENDPOINT")
  SANDBOX_CREATED=1
  run_setup_step "creating sandbox" \
    "${CLI[@]}" sandbox create --name "$SANDBOX_NAME" --from "$SANDBOX_IMAGE" --policy "$EXAMPLE_DIR/policy.yaml" --no-tty --detach -- sleep infinity
}

sx() {
  "${CLI[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- "$@"
}

# Raw TCP client: the sandbox boundary mediates the connection transparently.
RAW_CLIENT='
import socket, sys
host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
received = 0
try:
    s = socket.create_connection((host, port), timeout=60)
    s.sendall(("PULL %d\n" % count).encode())
    while received < count:
        chunk = s.recv(65536)
        if not chunk:
            break
        received += len(chunk)
except OSError as error:
    print("error=%s" % error)
print("received=%d" % received)
sys.exit(0 if received == count else 4)
'

raw_get() {
  sx python3 -c "$RAW_CLIENT" "$1" "$2" "$3"
}

http_get() {
  sx curl -sS -o /dev/null -w 'status=%{http_code} size=%{size_download}\n' --max-time 60 "$@"
}

run_suite() {
  local out started elapsed
  out="$(http_get http://host.openshell.internal:47080/bytes/1000000 2>&1)" || fail "baseline HTTP download: $out"
  [[ "$out" == *"status=200 size=1000000"* ]] || fail "baseline HTTP download: $out"
  printf 'PASS baseline HTTP 1MB under threshold (%s)\n' "$out"

  out="$(raw_get host.openshell.internal 47900 1000000 2>&1)" || fail "baseline raw TCP: $out"
  printf 'PASS baseline raw TCP 1MB under threshold (%s)\n' "$out"

  out="$(http_get http://host.openshell.internal:47081/bytes/1000000 2>&1)" || fail "control host: $out"
  printf 'PASS control key other_svc (%s)\n' "$out"

  printf 'INFO D2 burst: 200MB over tls: skip at 10MB/s, policy budget 20MB per 60s\n'
  started=$(date +%s.%N)
  out="$(http_get -k --limit-rate 10M https://host.openshell.internal:47443/bytes/200000000 2>&1)" && fail "D2 burst was not cut: $out"
  elapsed=$(echo "$(date +%s.%N) - $started" | bc)
  [[ "$out" != *"size=200000000"* ]] || fail "D2 burst was not cut: $out"
  printf 'PASS D2 burst over tls: skip cut after %ss (%s)\n' "$elapsed" "$(echo "$out" | tr '\n' ' ')"

  out="$(raw_get host.openshell.internal 47900 1000 2>&1)" && fail "new raw TCP connection was not denied: $out"
  [[ "$out" == *"received=0"* ]] || fail "new raw TCP connection denial: $out"
  printf 'PASS new pkg_proxy raw TCP connection denied (%s)\n' "$out"

  out="$(http_get http://host.openshell.internal:47080/bytes/1000 2>&1)" || true
  # Transparently mediated connections have no CONNECT to answer: a
  # preflight denial closes the connection before any response.
  [[ "$out" == *"status=403"* || "$out" == *"Empty reply"* ]] || fail "new HTTP request denied: $out"
  printf 'PASS new pkg_proxy HTTP request denied (%s)\n' "$(echo "$out" | tr '\n' ' ')"

  out="$(http_get http://host.openshell.internal:47081/bytes/1000000 2>&1)" || fail "control host after trip: $out"
  printf 'PASS control key other_svc still allowed (%s)\n' "$out"

  # Split transfer in a fresh sandbox: each connection ends before its first
  # stats tick, so only the end totals count toward the window.
  "${CLI[@]}" sandbox delete "$SANDBOX_NAME" >>"$SETUP_LOG" 2>&1 || true
  SANDBOX_NAME="${SANDBOX_NAME}b"
  create_sandbox
  local count denied=0
  for count in $(seq 1 40); do
    out="$(raw_get host.openshell.internal 47900 1000000 2>&1)" || true
    if [[ "$out" == *"received=0"* ]]; then
      denied="$count"
      break
    fi
  done
  [[ "$denied" -gt 0 ]] || fail "split transfer of 40 x 1MB raw TCP connections was not stopped"
  printf 'PASS split transfer denied at connection %s (%s MB through)\n' "$denied" "$((denied - 1))"

  # The budget lives in the policy: changing the policy changes it.
  sed 's/max_bytes: 20MB/max_bytes: lots/' "$EXAMPLE_DIR/policy.yaml" >"$SMOKE_TMP_DIR/invalid.yaml"
  out="$("${CLI[@]}" policy set "$SANDBOX_NAME" --policy "$SMOKE_TMP_DIR/invalid.yaml" 2>&1)" \
    && fail "invalid budget was accepted: $out"
  [[ "$out" == *"invalid byte size"* ]] || fail "invalid budget rejection: $out"
  printf 'PASS invalid budget rejected by ValidateConfig (%s)\n' "$(echo "$out" | grep -m1 'invalid byte size')"

  out="$(http_get --limit-rate 10M http://host.openshell.internal:47081/bytes/15000000 2>&1)" \
    || fail "15MB on other_svc under its 50MB budget: $out"
  printf 'PASS 15MB on other_svc under its 50MB policy budget (%s)\n' "$out"

  sed 's/max_bytes: 50MB/max_bytes: 10MB/' "$EXAMPLE_DIR/policy.yaml" >"$SMOKE_TMP_DIR/tight.yaml"
  run_setup_step "lowering the other_svc budget to 10MB in the policy" \
    "${CLI[@]}" policy set "$SANDBOX_NAME" --policy "$SMOKE_TMP_DIR/tight.yaml" --wait
  out="$(http_get --limit-rate 10M http://host.openshell.internal:47081/bytes/15000000 2>&1)" \
    && fail "15MB on other_svc was not cut after lowering its budget: $out"
  printf 'PASS same 15MB on other_svc cut after the policy lowered its budget to 10MB (%s)\n' "$(echo "$out" | tr '\n' ' ')"

  grep -E 'TRIP|deny' "$MIDDLEWARE_LOG" || true
  echo "ALL PASS egress-usage smoke"
}

print_ready() {
  cat <<READY

READY egress-usage TCP middleware

Gateway endpoint:    $GATEWAY_ENDPOINT
Middleware endpoint: http://$SERVICE_HOST:$MIDDLEWARE_PORT
Sandbox:             $SANDBOX_NAME
Gateway config:      $GATEWAY_CONFIG
Middleware log:      $MIDDLEWARE_LOG
Policy:              $EXAMPLE_DIR/policy.yaml

Change the budget by editing the policy's config and applying it:
  ${CLI[*]} policy set $SANDBOX_NAME --policy <edited policy.yaml> --wait

Burst over tls: skip (cut at the policy budget, 20MB per 60s):
  ${CLI[*]} sandbox exec --name $SANDBOX_NAME --no-tty -- curl -k --limit-rate 10M -o /dev/null https://host.openshell.internal:47443/bytes/200000000

Press Ctrl-C to clean up.
READY
}

cd "$ROOT"
for command in cargo curl jq openssl mise docker bc python3; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done
ROOT_TARGET_DIR="$(cargo_target_dir "$ROOT/Cargo.toml")"
EXAMPLE_TARGET_DIR="$(cargo_target_dir "$EXAMPLE_DIR/Cargo.toml")"
GATEWAY_BIN="$ROOT_TARGET_DIR/debug/openshell-gateway"
CLI_BIN="$ROOT_TARGET_DIR/debug/openshell"
MIDDLEWARE_BIN="$EXAMPLE_TARGET_DIR/debug/supervisor-middleware-egress-usage"
if [[ -z "${EGRESS_USAGE_SUPERVISOR_IMAGE:-}" ]]; then
  run_setup_step "building gateway" cargo build --quiet -p openshell-gateway --bin openshell-gateway
  run_setup_step "building Linux sandbox supervisor image" \
    env -u CI -u DOCKER_PLATFORM -u DOCKER_PUSH -u DOCKER_OUTPUT \
    CONTAINER_ENGINE=docker PREBUILT_AUTO_STAGE=1 \
    IMAGE_REGISTRY=localhost/openshell-egress-usage IMAGE_TAG="$RUN_ID" \
    mise run docker:build:supervisor
  run_setup_step "building CLI" cargo build --quiet -p openshell-cli --bin openshell
fi
run_setup_step "building egress-usage service" cargo build --quiet --manifest-path "$EXAMPLE_DIR/Cargo.toml"
generate_gateway_jwt_bundle
start_upstream
start_middleware
start_gateway
create_sandbox

if [[ "$RUN_TEST_SUITE" -eq 1 ]]; then
  run_suite
else
  print_ready
  while kill -0 "$GATEWAY_PID" 2>/dev/null && kill -0 "$MIDDLEWARE_PID" 2>/dev/null; do sleep 1; done
  fail "gateway or middleware exited"
fi
