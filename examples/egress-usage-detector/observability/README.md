<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Collector fan-out: detector + Grafana

A local OpenTelemetry Collector receives OCSF records and spans from the
gateway and every sandbox supervisor, then fans them out:

```
supervisors ──OTLP──► collector :4317 ─┬─ logs (class 4001/4002 only) ──► detector :14317 ──► openshell CLI
gateway     ──OTLP──►                  ├─ logs, traces ─────────────────► Grafana LGTM (Loki, Tempo)
                                       └─ signaltometrics ──► metrics ──► Grafana LGTM (Prometheus)
```

- `compose.yaml` runs the collector (host network, so Docker supervisors reach
  `127.0.0.1:4317`) and `grafana/otel-lgtm` (Grafana on `127.0.0.1:3000`, its
  own OTLP receiver on `127.0.0.1:24317`).
- `collector.yaml` derives `openshell_egress_bytes_in` and
  `openshell_egress_bytes_out` from the promoted `ocsf.traffic.*` attributes,
  labeled by `openshell_sandbox_id`, `openshell_policy`, and
  `destination_address`.
- `run-gateway.sh` starts a Docker gateway with OTLP export to the collector.
- `dashboard.json` shows egress rates, five-minute totals, and the raw events.

## Run

```shell
examples/egress-usage-detector/observability/up.sh
uv run examples/egress-usage-detector/detector.py --listen 127.0.0.1:14317 \
  --openshell "$PWD/target/debug/openshell" --gateway spike-01b --reaction deny
examples/egress-usage-detector/observability/run-gateway.sh
openshell --gateway spike-01b settings set --global --yes --key ocsf_traffic_interval_secs --value 5
```

Open http://127.0.0.1:3000/d/openshell-egress. Anonymous access is enabled as
Admin, which is acceptable for local use only. Tear down with
`docker compose -f examples/egress-usage-detector/observability/compose.yaml down`.

The collector queues and retries per exporter, so a stopped detector does not
block Grafana, and the reverse is also true.

## Useful queries

- PromQL: `sum by (openshell_sandbox_id, openshell_policy) (increase(openshell_egress_bytes_in[5m]))`
- LogQL: `{service_name="openshell-supervisor"} | ocsf_class_uid="4001" | ocsf_activity_id=~"2|6"`

## Caveats

- The derived counters receive a sample only when events arrive. The first
  delta of a series has no earlier sample, so `increase()` undercounts short
  bursts, and a single Close-only burst may not show a rate at all. Detection
  belongs on the events (the detector) or on longer windows.
- The metric labels include the sandbox id, not the sandbox name. Join on
  Loki's `container.name` in the event body when you need names.
