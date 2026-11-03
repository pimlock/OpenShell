<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Collector fan-out: detector + Grafana

A local OpenTelemetry Collector receives OCSF records and spans from the
gateway and every sandbox supervisor, then fans them out:

```
supervisors ──OTLP──► collector :4317 ─┬─ logs (class 4001/4002 only) ──► detector :14317 ──► openshell CLI
gateway     ──OTLP──►                  └─ logs, traces ─────────────────► Grafana LGTM (Loki, Tempo)
```

- `compose.yaml` runs the collector (host network, so Docker supervisors reach
  `127.0.0.1:4317`) and `grafana/otel-lgtm` (Grafana on `127.0.0.1:3000`, its
  own OTLP receiver on `127.0.0.1:24317`).
- `collector.yaml` filters on the `ocsf.class_uid` attribute for the detector
  and sends everything to LGTM. It does not parse the OCSF body.
- `run-gateway.sh` starts a Docker gateway with OTLP export to the collector
  and push config delivery.
- `dashboard.json` sums the `traffic` deltas from Loki per sandbox name and
  policy key, and lists the raw events.

## Run

```shell
examples/egress-usage-detector/observability/up.sh
(cd examples/egress-usage-detector && cargo build)
examples/egress-usage-detector/target/debug/egress-usage-detector \
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

Bytes per sandbox and policy key over five minutes:

```logql
sum by (sandbox, policy) (sum_over_time(
  {service_name="openshell-supervisor"} | ocsf_class_uid="4001" | ocsf_activity_id=~"2|6"
  | json bytes="traffic.bytes", sandbox="container.name", policy="firewall_rule.name"
  | unwrap bytes [5m]))
```

Raw Traffic and Close events:
`{service_name="openshell-supervisor"} | ocsf_class_uid="4001" | ocsf_activity_id=~"2|6"`.

See the detector README for why there is no Prometheus path and for the other
shortcuts in this setup.
