<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Egress usage detector (spike)

A minimal stream detector for sandbox egress volume. It receives OCSF events as
OTLP/gRPC log records from sandbox supervisors and reacts through the
`openshell` CLI when a threshold trips.

Supervisors report bytes per connection as OCSF Network Activity events: a
`Close` event for every connection with `cumulative_traffic` totals, and, when
the `ocsf_traffic_interval_secs` setting is non-zero, a `Traffic` event per
interval for connections that moved bytes. Each event's `traffic` holds the
bytes since the connection's previous event.

## Run

Start the detector where the gateway's OCSF OTLP endpoint points, then start
the gateway with `[openshell.gateway.otlp.ocsf] enabled = true`.
`mise run gateway:docker` enables it automatically when something listens on
`127.0.0.1:4317`.

```shell
uv run examples/egress-usage-detector/detector.py \
  --listen 127.0.0.1:4317 --gateway docker-dev \
  --d2-bytes 20MB --window-secs 60 --reaction deny
openshell settings set --global --yes --key ocsf_traffic_interval_secs --value 5
```

- D2 sums `traffic` bytes per sandbox and policy key over `--window-secs`.
- D1 counts distinct sandboxes sending HTTP `PUT` to one host over
  `--d1-window-secs` and trips above `--d1-writers`. It needs L7-inspected
  endpoints, which emit HTTP Activity events.
- `--reaction stop` stops the sandbox. `--reaction deny` removes the policy key
  for D2, which also closes in-flight connections once the supervisor loads the
  new policy, and appends a `PUT` deny rule for D1.
- `--dry-run` logs reactions without calling the CLI; `--print-events` logs the
  JSON of every traffic event.

The detector only implements the OTLP logs service. Trace export to the same
endpoint fails with `UNIMPLEMENTED`, which is harmless.
