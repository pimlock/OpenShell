# /// script
# requires-python = ">=3.11"
# dependencies = ["grpcio>=1.60", "opentelemetry-proto>=1.25"]
# ///
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Minimal stream detector for OpenShell egress volume (spike 01b).

Receives OCSF events as OTLP/gRPC log records from sandbox supervisors,
keeps sliding windows in memory, and reacts through the OpenShell CLI:

- D2: bytes per sandbox + policy key over a window, from Network Activity
  Traffic (6) and Close (2) events. Each event's ``traffic`` is the delta
  since the connection's previous report, so sums never double count.
- D1: distinct sandboxes sending HTTP PUT to one host over a window, from
  HTTP Activity (4002) events.

Reactions (``--reaction``):

- ``stop``: ``openshell sandbox stop <sandbox>``.
- ``deny``: D2 removes the policy key (``policy update --remove-rule``),
  which also cuts in-flight relays because the policy generation changes.
  D1 appends a PUT deny rule to the policy key for every writer, restating
  the rule's binaries as the CLI requires.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import sys
import threading
import time
from concurrent import futures

import grpc
from opentelemetry.proto.collector.logs.v1 import logs_service_pb2, logs_service_pb2_grpc

NETWORK_ACTIVITY = 4001
HTTP_ACTIVITY = 4002
ACTIVITY_CLOSE = 2
ACTIVITY_TRAFFIC = 6


def log(message: str) -> None:
    stamp = time.strftime("%H:%M:%S", time.localtime()) + f".{int(time.time() * 1000) % 1000:03d}"
    print(f"{stamp} {message}", flush=True)


def parse_size(raw: str) -> int:
    units = {"KB": 10**3, "MB": 10**6, "GB": 10**9, "KIB": 2**10, "MIB": 2**20, "GIB": 2**30}
    text = raw.strip().upper()
    for suffix, factor in sorted(units.items(), key=lambda kv: -len(kv[0])):
        if text.endswith(suffix):
            return int(float(text[: -len(suffix)]) * factor)
    return int(text)


class Detector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.lock = threading.Lock()
        # (sandbox, policy) -> deque[(received_s, bytes, event_end_ms)]
        self.d2: dict[tuple[str, str], collections.deque] = collections.defaultdict(collections.deque)
        # host -> {sandbox: last_put_s}
        self.d1: dict[str, dict[str, float]] = collections.defaultdict(dict)
        self.tripped: set[tuple] = set()
        self.seen_uids: collections.OrderedDict[str, None] = collections.OrderedDict()

    # -- ingestion -----------------------------------------------------------

    def ingest(self, event: dict) -> None:
        uid = (event.get("metadata") or {}).get("uid")
        if uid:
            # OTLP export is at least once; deduplicate on metadata.uid.
            if uid in self.seen_uids:
                return
            self.seen_uids[uid] = None
            if len(self.seen_uids) > 100_000:
                self.seen_uids.popitem(last=False)
        class_uid = event.get("class_uid")
        activity = event.get("activity_id")
        if class_uid == NETWORK_ACTIVITY and activity in (ACTIVITY_TRAFFIC, ACTIVITY_CLOSE):
            self.on_traffic(event)
        elif class_uid == HTTP_ACTIVITY:
            self.on_http(event)

    def on_traffic(self, event: dict) -> None:
        if self.args.print_events:
            log("event " + json.dumps(event, sort_keys=True))
        traffic = event.get("traffic")
        if not traffic:
            return
        if self.args.direction == "in":
            amount = traffic.get("bytes_in", 0)
        elif self.args.direction == "out":
            amount = traffic.get("bytes_out", 0)
        else:
            amount = traffic.get("bytes", 0)
        if amount <= 0:
            return
        sandbox = sandbox_name(event)
        policy = (event.get("firewall_rule") or {}).get("name", "-")
        if self.args.policy and policy not in self.args.policy:
            return
        now = time.time()
        key = (sandbox, policy)
        with self.lock:
            window = self.d2[key]
            window.append((now, amount, event.get("end_time") or event.get("time")))
            while window and window[0][0] < now - self.args.window_secs:
                window.popleft()
            total = sum(item[1] for item in window)
            if self.args.verbose:
                log(f"traffic {sandbox}/{policy} +{amount} window={total}")
            if total < self.args.d2_bytes or ("d2", key) in self.tripped:
                return
            self.tripped.add(("d2", key))
        event_ms = event.get("end_time") or event.get("time") or int(now * 1000)
        log(
            f"D2 TRIP sandbox={sandbox} policy={policy} window_bytes={total} "
            f">= {self.args.d2_bytes} in {self.args.window_secs}s "
            f"(event lag {now * 1000 - event_ms:.0f} ms)"
        )
        self.react_async("d2", sandbox, policy, event_ms, now, event)

    def on_http(self, event: dict) -> None:
        request = event.get("http_request") or {}
        if (request.get("http_method") or "").upper() != "PUT":
            return
        url = request.get("url") or {}
        host = url.get("hostname") or (event.get("dst_endpoint") or {}).get("domain") or "-"
        port = url.get("port") or (event.get("dst_endpoint") or {}).get("port")
        if self.args.d1_host and host != self.args.d1_host:
            return
        sandbox = sandbox_name(event)
        policy = (event.get("firewall_rule") or {}).get("name", "-")
        now = time.time()
        with self.lock:
            writers = self.d1[host]
            writers[sandbox] = now
            for name, seen in list(writers.items()):
                if seen < now - self.args.d1_window_secs:
                    del writers[name]
            if len(writers) <= self.args.d1_writers or ("d1", host) in self.tripped:
                return
            self.tripped.add(("d1", host))
            offenders = sorted(writers)
        event_ms = event.get("time") or int(now * 1000)
        log(
            f"D1 TRIP host={host} distinct_put_writers={len(offenders)} > {self.args.d1_writers} "
            f"in {self.args.d1_window_secs}s: {', '.join(offenders)}"
        )
        for sandbox in offenders:
            self.react_async("d1", sandbox, policy, event_ms, now, event, host=host, port=port)

    # -- reaction ------------------------------------------------------------

    def react_async(self, *args, **kwargs) -> None:
        threading.Thread(target=self.react, args=args, kwargs=kwargs, daemon=True).start()

    def react(self, kind, sandbox, policy, event_ms, tripped_s, event, host=None, port=None) -> None:
        cli = [self.args.openshell]
        if self.args.gateway:
            cli += ["--gateway", self.args.gateway]
        if self.args.reaction == "stop":
            commands = [cli + ["sandbox", "stop", sandbox]]
        elif kind == "d2":
            commands = [cli + ["policy", "update", sandbox, "--remove-rule", policy]]
        else:
            target = f"{host}:{port}" if port else host
            commands = [
                cli
                + [
                    "policy", "update", sandbox,
                    "--add-deny", f"{target}:PUT:/**",
                    "--rule-name", policy,
                ]
                + self.binary_scope(cli, sandbox, policy)
            ]
        if self.args.dry_run:
            for command in commands:
                log(f"DRY RUN {' '.join(command)}")
            return
        env = self.cli_env()
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, env=env)
            done = time.time()
            status = "ok" if result.returncode == 0 else f"exit {result.returncode}"
            log(
                f"REACT {kind.upper()} {self.args.reaction} sandbox={sandbox} [{status}] "
                f"detect->react {(done - tripped_s) * 1000:.0f} ms, "
                f"supervisor event->react {done * 1000 - event_ms:.0f} ms: {' '.join(command[1:])}"
            )
            if result.returncode != 0:
                log(f"  stderr: {result.stderr.strip()}")


    def binary_scope(self, cli: list[str], sandbox: str, policy: str) -> list[str]:
        """CLI flags naming the rule's complete binary list.

        An L7 append must restate the target rule's binaries exactly, so read
        them from the sandbox's base policy. A rule without binaries allows
        any binary.
        """
        result = subprocess.run(
            cli + ["policy", "get", sandbox, "--base", "-o", "json"],
            capture_output=True, text=True, env=self.cli_env(),
        )
        try:
            rule = json.loads(result.stdout)["policy"]["network_policies"][policy]
        except (json.JSONDecodeError, KeyError, TypeError):
            log(f"  could not read binaries of {sandbox}/{policy}: {result.stderr.strip()}")
            return ["--any-binary"]
        paths = [binary["path"] for binary in rule.get("binaries", []) if binary.get("path")]
        if not paths:
            return ["--any-binary"]
        return [flag for path in paths for flag in ("--binary", path)]

    def cli_env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.args.workspace:
            env["OPENSHELL_WORKSPACE"] = self.args.workspace
        return env


def sandbox_name(event: dict) -> str:
    container = event.get("container") or {}
    return container.get("name") or container.get("uid") or "-"


class LogsService(logs_service_pb2_grpc.LogsServiceServicer):
    def __init__(self, detector: Detector) -> None:
        self.detector = detector

    def Export(self, request, context):  # noqa: N802 (gRPC method name)
        for resource_logs in request.resource_logs:
            for scope_logs in resource_logs.scope_logs:
                for record in scope_logs.log_records:
                    body = record.body.string_value
                    if not body:
                        continue
                    try:
                        event = json.loads(body)
                    except json.JSONDecodeError:
                        continue
                    self.detector.ingest(event)
        return logs_service_pb2.ExportLogsServiceResponse()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", default="0.0.0.0:4317", help="OTLP/gRPC listen address")
    parser.add_argument("--reaction", choices=["stop", "deny"], default="deny")
    parser.add_argument("--openshell", default="openshell", help="openshell CLI binary")
    parser.add_argument("--gateway", default=None, help="gateway name for the CLI (--gateway)")
    parser.add_argument("--workspace", default=None, help="workspace of the sandboxes (OPENSHELL_WORKSPACE)")
    parser.add_argument("--dry-run", action="store_true", help="log reactions without calling the CLI")
    parser.add_argument("--verbose", action="store_true", help="log every traffic event")
    parser.add_argument("--print-events", action="store_true", help="log the JSON of every traffic event")
    d2 = parser.add_argument_group("D2: bytes per sandbox + policy key")
    d2.add_argument("--d2-bytes", type=parse_size, default=parse_size("20MB"), help="threshold, e.g. 20MB")
    d2.add_argument("--window-secs", type=float, default=60.0)
    d2.add_argument("--direction", choices=["in", "out", "both"], default="both")
    d2.add_argument("--policy", action="append", help="only watch these policy keys (repeatable)")
    d1 = parser.add_argument_group("D1: distinct PUT writers per host")
    d1.add_argument("--d1-writers", type=int, default=5, help="trip when writers exceed this")
    d1.add_argument("--d1-window-secs", type=float, default=300.0)
    d1.add_argument("--d1-host", default=None, help="only watch this host")
    args = parser.parse_args()

    detector = Detector(args)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    logs_service_pb2_grpc.add_LogsServiceServicer_to_server(LogsService(detector), server)
    server.add_insecure_port(args.listen)
    server.start()
    log(
        f"listening on {args.listen}; reaction={args.reaction} d2={args.d2_bytes}B/{args.window_secs:g}s "
        f"({args.direction}) d1>{args.d1_writers} writers/{args.d1_window_secs:g}s"
    )
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
