#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run a standalone Docker-backed gateway whose supervisors export OCSF records
# (and spans) to the collector in compose.yaml on 127.0.0.1:4317.
#
# Unlike `mise run gateway:docker`, the OTLP tables are always written: that
# task probes the port with lsof, which cannot see the root-owned collector.
#
# Requires the supervisor and sandbox images named below; build them with
#   CONTAINER_ENGINE=docker IMAGE_TAG=spike-01b mise run build:docker:supervisor
#   CONTAINER_ENGINE=docker IMAGE_TAG=spike-01b mise run build:docker:sandbox

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18081}"
GATEWAY_NAME="${OPENSHELL_DOCKER_GATEWAY_NAME:-spike-01b}"
STATE_DIR="${OPENSHELL_DOCKER_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-${GATEWAY_NAME}}"
SANDBOX_LABEL="${OPENSHELL_SANDBOX_NAMESPACE:-${GATEWAY_NAME}}"
SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-openshell/supervisor:spike-01b}"
SANDBOX_RUNTIME_IMAGE="${OPENSHELL_SANDBOX_RUNTIME_IMAGE:-openshell/sandbox:spike-01b}"
COLLECTOR="${OPENSHELL_OTLP_COLLECTOR:-http://127.0.0.1:4317}"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"

for image in "${SUPERVISOR_IMAGE}" "${SANDBOX_RUNTIME_IMAGE}"; do
  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    echo "ERROR: image ${image} not found; see the header of this script" >&2
    exit 1
  fi
done

cargo build -p openshell-gateway --bin openshell-gateway

TLS_DIR="${STATE_DIR}/tls"
"${GATEWAY_BIN}" generate-certs \
  --output-dir "${TLS_DIR}" \
  --server-san "127.0.0.1" \
  --server-san "localhost" \
  --server-san "host.openshell.internal"

mkdir -p "${STATE_DIR}"
CONFIG_PATH="${STATE_DIR}/gateway.toml"
cat >"${CONFIG_PATH}" <<EOF
[openshell]
version = 2

[openshell.gateway]
name = "${GATEWAY_NAME}"
compute_driver = "docker"
disable_tls = true
# Push policy updates over the supervisor session so deny reactions take
# effect in about a second instead of at the next settings poll.
config_delivery_mode = "${OPENSHELL_CONFIG_DELIVERY_MODE:-push}"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"

# Spans and OCSF records from the gateway and every supervisor go to the
# collector, which fans OCSF out to the detector and Grafana LGTM.
[openshell.gateway.otlp]
endpoint = "${COLLECTOR}"

[openshell.gateway.otlp.ocsf]
enabled = true

[openshell.drivers.docker]
default_image = "${OPENSHELL_SANDBOX_IMAGE:-nvcr.io/nvidia/base/ubuntu:24.04}"
supervisor_image = "${SUPERVISOR_IMAGE}"
sandbox_runtime_image = "${SANDBOX_RUNTIME_IMAGE}"
image_pull_policy = "if_not_present"
# A unique label keeps other local gateways from reaping these sandboxes.
sandbox_label = "${SANDBOX_LABEL}"
app_armor_profile = "Unconfined"
EOF

GATEWAY_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/openshell/gateways/${GATEWAY_NAME}"
mkdir -p "${GATEWAY_DIR}"
cat >"${GATEWAY_DIR}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "http://127.0.0.1:${PORT}",
  "is_remote": false,
  "gateway_port": ${PORT},
  "auth_mode": "plaintext"
}
EOF

echo "Gateway ${GATEWAY_NAME} on http://127.0.0.1:${PORT}, OTLP to ${COLLECTOR}"
exec "${GATEWAY_BIN}" \
  --config "${CONFIG_PATH}" \
  --port "${PORT}" \
  --log-level "${OPENSHELL_LOG_LEVEL:-info}" \
  --compute-driver docker \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
