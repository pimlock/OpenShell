<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware Egress Usage (spike)

> [!WARNING]
> Spike for TCP connection hooks (`TcpHooks.EvaluateConnection`). The contract is not settled.

The service binds `TCP_CONNECTION` at `PRE_CONNECT` and requires the `openshell.supervisor-middleware.tcp-hooks` capability. For every admitted upstream connection its selector matches, OpenShell sends a preflight before dialing. The service selects STATS mode and receives cumulative upstream byte totals at its interval. It sums them into a sliding window per sandbox and network policy key. When a window passes `--max-bytes`, it closes that key's open connections and denies new ones for `--block-for`, with reason code `egress_budget_exceeded`.

Covers raw TCP, `tls: skip`, terminated TLS, and plain HTTP the same way, because bytes are counted at the upstream socket.

## Run the smoke suite

```shell
./examples/supervisor-middleware-egress-usage/smoke.sh --test-suite
```

The script builds the gateway, CLI, and a local supervisor image, starts the host-run upstream (`upstream.py`), the service, and a Docker-driver gateway, creates a sandbox with `policy.yaml`, and checks:

- 1 MB over HTTP and raw TCP, and on the `other_svc` key, pass.
- A 200 MB download over `tls: skip` at 10 MB/s is cut shortly after 20 MB.
- New `pkg_proxy` connections are then denied; `other_svc` still passes.

Set `EGRESS_USAGE_SUPERVISOR_IMAGE` to reuse a built supervisor image and skip the builds.

## Run manually

```shell
cd examples/supervisor-middleware-egress-usage
cargo run -- --bind 0.0.0.0:50061 --max-bytes 20MB --window 60s --interval 5s --block-for 300s
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
