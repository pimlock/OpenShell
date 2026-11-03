#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start the collector and Grafana LGTM, then import the egress dashboard.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
docker compose up -d
for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:3000/api/health >/dev/null && break
  sleep 2
done
python3 -c 'import json,sys; print(json.dumps({"dashboard": json.load(open("dashboard.json")), "overwrite": True}))' |
  curl -sf -X POST -H 'Content-Type: application/json' --data-binary @- \
    http://127.0.0.1:3000/api/dashboards/db >/dev/null
echo "Grafana: http://127.0.0.1:3000/d/openshell-egress"
