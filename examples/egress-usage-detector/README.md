<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Egress usage detector (spike 01b)

An example external detector for sandbox egress. It receives OCSF events as
OTLP/gRPC log records, keeps sliding windows in memory, and reacts through the
`openshell` CLI when a rule trips.

Supervisors report bytes per upstream connection as OCSF Network Activity
events: a `Close` event for every connection with `cumulative_traffic` totals,
and, when the `ocsf_traffic_interval_secs` setting is non-zero, a `Traffic`
event per interval for connections that moved bytes. Each event's `traffic`
holds the bytes since the connection's previous event, so sums never double
count.

## Layout

- `src/detect.rs`: the rules, with no I/O and no event format. Callers pick the
  keys and pass the clock, so the same rules can sit behind OCSF events (here)
  or middleware hooks (spike 02b, `examples/supervisor-middleware-egress-usage`).
  - `VolumeRule`: bytes per key over a sliding window (D2).
  - `DistinctRule`: distinct members per group over a window (D1).
- `src/main.rs`: OTLP logs receiver. It parses each record body into
  `openshell_ocsf::OcsfEvent` and feeds the rules.
- `src/react.rs`: reactions through the CLI.
- `observability/`: collector fan-out to this detector and Grafana LGTM.

## Rules and reactions

| Rule | Input | Key | Trips when | `--reaction deny` | `--reaction stop` |
|---|---|---|---|---|---|
| Volume (D2) | Network Activity Traffic (6) and Close (2) | sandbox name, policy key | `traffic` bytes in `--window` exceed `--max-bytes` | `policy update <sb> --remove-rule <key>` | `sandbox stop <sb>` |
| Writers (D1) | HTTP Activity (4002), method PUT | host | distinct sandboxes in `--writers-window` exceed `--max-writers` | per writer: `policy update <sb> --add-deny host:port:PUT:/** --rule-name <key>` plus the rule's binaries | `sandbox stop` per writer |

- Removing the policy key also cuts in-flight connections: the policy
  generation guard closes every relay once the supervisor loads the new
  revision.
- Writers needs `protocol: rest` endpoints; only inspected endpoints emit HTTP
  Activity.
- A tripped key or host is ignored for `--cooldown` (default 300s).
- `--direction in|out|both` picks which bytes count. `--policy` limits Volume
  to some policy keys. `--writers-host` limits Writers to one host.
- `--dry-run` logs reactions without calling the CLI. `--verbose` logs every
  traffic event.
- Each reaction logs `detect->react` (rule trip to CLI exit) and
  `supervisor event->react` (the event's `end_time` to CLI exit).

## Run

Run a gateway with push config delivery (`config_delivery_mode = "push"`);
with the default polling, a deny takes effect only at the next settings poll,
5 to 14 seconds later. `observability/run-gateway.sh` writes such a gateway.

```shell
cd examples/egress-usage-detector
cargo build
target/debug/egress-usage-detector --gateway spike-01b --reaction deny \
  --max-bytes 20MB --window 60s
openshell --gateway spike-01b settings set --global --yes --key ocsf_traffic_interval_secs --value 5
```

Point the gateway's OCSF OTLP export (`[openshell.gateway.otlp] endpoint` plus
`[openshell.gateway.otlp.ocsf] enabled = true`) at the detector's `--listen`
address (default `127.0.0.1:14317`), or at the collector in `observability/`,
which forwards Network Activity and HTTP Activity to the detector.

## Measured locally

Docker driver, push delivery, interval 5 s, through the collector, 100 MB
download at about 4 MB/s, threshold 20 MB / 60 s:

| Step | Result |
|---|---|
| Trip | second Traffic event, 33.0 MB in the window, event lag 596 ms |
| Reaction | `--remove-rule` returned 39 ms after the trip, 636 ms after the supervisor event |
| Cut | relay closed about 0.6 s later; 34.4 MB delivered |
| New connection | denied (`PermissionError 13`) |
| Writers | one PUT with `--max-writers 0`: tripped, deny appended with `--binary /**`, 525 ms after the event |

## Shortcuts taken in this spike

The OpenShell implementation is unchanged by these notes. They record where the
spike took a shortcut and what we would do instead.

### Routing traffic events by tracing target

Traffic and Close events use a separate tracing target, `ocsf_traffic`. The
JSONL file layer and the OTLP layer accept it; the shorthand console and file,
the stderr OCSF-JSON console, and gateway log push (`openshell logs`) skip it.
This keeps per-connection volume out of the places people read.

The general version is a delivery class chosen at emit time, independent of
OCSF severity and of the tracing level:

| Class | Meaning | Sinks by default |
|---|---|---|
| `audit` (default) | security decisions and lifecycle | all |
| `telemetry` | high-volume accounting | JSONL file, OTLP |

Each sink declares the classes it accepts, which gives one place to configure
later. The class can stay a tracing target, since targets are static metadata
that per-layer filters match cheaply.

Alternatives we rejected:

- OCSF `severity_id = 99` ("Other") as the switch. In OCSF it means "a severity
  outside the enum", not "low priority", and SIEM rules that filter on
  `severity_id` would misread routine events.
- The tracing level (`debug!`). `--log-level debug` drives the console filter,
  so debugging a supervisor would print every Traffic event.

The delivery class could still set the OTLP severity: `telemetry` records
exported as OTLP `DEBUG` show up as debug in Loki and Grafana, while the OCSF
body keeps `severity_id = 1`.

### OTLP `severity_text` carries OCSF labels

The OTLP mapping sets `severity_text` to the OCSF label (`Informational`,
`Low`, `Medium`, ...). Loki copies it verbatim into `detected_level`, and
Grafana does not recognize `Low` or `Medium` as log levels. Setting
`severity_text` to the OTel name of the band already in `severity_number`
(`INFO`, `WARN`, `ERROR`, `FATAL`) fixes level coloring and filters; the exact
OCSF level stays in `ocsf.severity_id`.

### Attributes on the OTLP record

The OTLP record carries the OCSF JSON as its body plus a few routing
attributes for every OCSF class: `ocsf.class_uid`, `ocsf.activity_id`,
`ocsf.severity_id`, `ocsf.metadata.uid`, and `openshell.sandbox.id`. An earlier
revision of this spike also promoted `destination.*`, `openshell.policy`,
`ocsf.connection_info.uid`, and `ocsf.traffic.bytes_*`. Those served only the
Prometheus path below, so they were removed. Consumers that need other fields
can:

- read the body, as this detector does;
- extract fields in the collector with OTTL, for example
  `merge_maps(log.cache, ParseJSON(log.body), "upsert")` followed by `set`
  statements, scoped with `conditions` to the classes they need;
- use LogQL `| json` in Loki.

A supervisor-side "promote these fields" setting would duplicate collector
extraction on every supervisor and add configuration that must reach them.
Sending the body as an OTLP map instead of a JSON string would let OTTL and
receivers address fields without parsing, but it changes the wire contract for
consumers that read the string.

### Prometheus versus Loki

An earlier revision derived `openshell_egress_bytes_{in,out}` counters in the
collector (`signaltometrics` plus `deltatocumulative`). It was removed:

- A new series has no earlier sample, so `increase()` lost the first delta of
  every series and undercounted short bursts.
- Running totals lived in collector memory and reset with the collector.
- Labels were limited to sandbox id, policy, and destination, and
  `destination_address` has unbounded cardinality.

Loki sums the per-event deltas exactly (`sum_over_time(... | json ... | unwrap
...)`) and reaches every OCSF field, which the dashboard now uses. Prometheus
remains the better store for long budgets and baselines (hourly or daily totals,
"10x the weekly average"); the counters should then come from the supervisor as
cumulative values, not be derived from events in the collector.

### Grafana alerts

Grafana alert rules could run Volume and Writers on Loki, plus deny spikes and
long-window budgets. They would be a second, slower layer, not a replacement:
rules evaluate every 10 s to 1 min, so alerts land 15 to 75 s after a crossing,
and a contact point can only call a webhook, so blocking still needs code that
turns alert labels into CLI calls.

### Measurement

- Counts are upstream socket bytes: transport bytes, including TLS overhead and
  HTTP framing, after credential injection, not split per HTTP request.
- The proxy reads ahead into its buffers, so a connection counts what left the
  upstream, not what the workload consumed. A client that read 2 MB and closed
  counted about 4.7 MB.
- `actor.process.pid` is 0 when the decision has no PID, and IP-literal hosts
  land in `dst_endpoint.domain`.

### Supervisor and transport

- Dedicated supervisor only. A shared multi-sandbox supervisor would emit with
  the right context but share one interval setting.
- No registry cap or event volume limit. Traffic events share the supervisor's
  OTLP queue (10k records or 16 MiB) with security events, so a large fleet at
  a short interval can push security events into gap drops.
- No OCSF schema-validation tests and no published docs for the new fields or
  the setting.

### Detector

- Reactions shell out to the CLI instead of calling the gateway API through
  `openshell-sdk`.
- State is in memory and lost on restart; deduplication remembers the last
  100,000 `metadata.uid` values.
- The receiver implements only the OTLP logs service, so trace export pointed
  at it fails with `UNIMPLEMENTED`. It accepts gzip, which the collector's
  exporter uses by default.
- A Writers deny on an IP-literal REST endpoint was not enforced in the earlier
  evaluation; it works for hostname endpoints such as `host.openshell.internal`.
  Not investigated.
