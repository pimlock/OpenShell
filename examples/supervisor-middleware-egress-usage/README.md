<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware Egress Usage (spike)

> [!WARNING]
> Spike for TCP connection hooks (`TcpHooks.EvaluateConnection`). The contract is not settled.

The service binds `TCP_CONNECTION` at `PRE_CONNECT` and requires the `openshell.supervisor-middleware.tcp-hooks` capability. For every admitted upstream connection its selector matches, OpenShell sends a preflight before dialing. The service selects STATS mode and receives cumulative upstream byte totals at its interval. It sums them into a sliding window per sandbox and network policy key. When a window passes `max_bytes`, it closes that key's open connections and denies new ones for `block_for`, with reason code `egress_budget_exceeded`.

Covers raw TCP, `tls: skip`, terminated TLS, and plain HTTP the same way, because bytes are counted at the upstream socket.

## Configure limits in the policy

The limits come from the middleware's `config` in the sandbox policy, so changing the policy changes the budget.

> [!NOTE]
> The `config` shape below is for demonstration only. OpenShell passes `config` to the middleware service as an opaque structure and does not define its fields: each service defines and validates its own. This example's service reads the fields below.

```yaml
network_middlewares:
  egress-usage:
    middleware: egress-usage-example
    config:
      max_bytes: 20MB     # per sandbox and policy key
      window: 60s
      interval: 1s        # stats interval, 1s to 60s
      block_for: 120s
      direction: both     # both, in, or out
      policies:           # overrides for one network policy key
        other_svc:
          max_bytes: 50MB
    on_error: fail_closed
    endpoints:
      include:
        - host.openshell.internal
```

Every field is optional; the service flags supply defaults. Sizes accept `B`, `KB`, `MB`, `GB` (decimal) or a number of bytes; durations accept `ms`, `s`, `m` or a number of seconds. The gateway calls `ValidateConfig` when a policy is set, so an invalid value is rejected by `openshell policy set`. A policy update applies to connections opened after the sandbox loads it; open connections keep the limits they started with.

## Run the smoke suite

```shell
./examples/supervisor-middleware-egress-usage/smoke.sh --test-suite
```

The script builds the gateway, CLI, and a local supervisor image, starts the host-run upstream (`upstream.py`), the service, and a Docker-driver gateway, creates a sandbox with `policy.yaml`, and checks:

- 1 MB over HTTP and raw TCP, and on the `other_svc` key, pass.
- A 200 MB download over `tls: skip` at 10 MB/s is cut shortly after 20 MB.
- New `pkg_proxy` connections are then denied; `other_svc` still passes.
- 40 short 1 MB raw TCP connections in a second sandbox are denied after 20 MB.
- `policy set` with `max_bytes: lots` is rejected.
- 15 MB on `other_svc` passes under its 50 MB budget; after `policy set` lowers it to 10 MB, the same transfer is cut.

Set `EGRESS_USAGE_SUPERVISOR_IMAGE` to reuse a built supervisor image and skip the builds.

## Run manually

```shell
cd examples/supervisor-middleware-egress-usage
cargo run -- --bind 0.0.0.0:50061
```

Register it in the gateway TOML. `max_payload_bytes` is required by the config schema but unused by TCP bindings:

```toml
[[openshell.supervisor.middleware]]
name = "egress-usage-example"
grpc_endpoint = "http://<host-address>:50061"
allow_insecure_transport = true
max_payload_bytes = 65536
timeout = "500ms"
```

Select it in the sandbox policy with `network_middlewares`, as in `policy.yaml`. A TCP-only service may select `tls: skip` endpoints under `fail_closed`.
