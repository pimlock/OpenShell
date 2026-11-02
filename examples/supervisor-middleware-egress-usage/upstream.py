# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Package proxy stand-in for the egress-usage example.

Runs on the host. Docker sandboxes reach it as host.openshell.internal, so
policy keys are told apart by port.

- 47080 (pkg_proxy) and 47081 (other_svc): plain HTTP. GET /bytes/<n> streams
  n bytes. PUT or POST consumes the body and returns its length.
- 47443 (pkg_proxy): the same HTTP handler over TLS (cert and key from
  UPSTREAM_TLS_CERT and UPSTREAM_TLS_KEY), for tls: skip passthrough.
- 47900 (pkg_proxy): raw TCP. Send "PULL <n>\\n" to receive n bytes, or
  "PUSH\\n" followed by bytes and a half-close to receive the count. A stream
  that starts with an HTTP method is sniffed as HTTP, hence the verbs.
"""

import os
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHUNK = b"x" * 65536


def stream_bytes(write, count):
    while count > 0:
        piece = CHUNK[: min(count, len(CHUNK))]
        write(piece)
        count -= len(piece)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "bytes" and parts[1].isdigit():
            count = int(parts[1])
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(count))
            self.end_headers()
            try:
                stream_bytes(self.wfile.write, count)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _consume(self):
        length = int(self.headers.get("Content-Length", "0"))
        received = 0
        while received < length:
            data = self.rfile.read(min(65536, length - received))
            if not data:
                break
            received += len(data)
        body = f"{received}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_PUT = _consume
    do_POST = _consume

    def log_message(self, format, *args):
        print(f"{self.client_address[0]} {format % args}", flush=True)


class RawHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode(errors="replace").strip()
        try:
            if line.startswith("PULL "):
                stream_bytes(self.wfile.write, int(line[5:]))
            elif line == "PUSH":
                received = 0
                while True:
                    data = self.rfile.read1(65536)
                    if not data:
                        break
                    received += len(data)
                self.wfile.write(f"{received}\n".encode())
        except (BrokenPipeError, ConnectionResetError):
            pass
        print(f"raw {self.client_address[0]} {line}", flush=True)


class RawServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    bind = os.environ.get("UPSTREAM_BIND", "127.0.0.1")
    servers = [
        ThreadingHTTPServer((bind, 47080), Handler),
        ThreadingHTTPServer((bind, 47081), Handler),
        RawServer((bind, 47900), RawHandler),
    ]
    cert, key = os.environ.get("UPSTREAM_TLS_CERT"), os.environ.get("UPSTREAM_TLS_KEY")
    if cert and key:
        tls = ThreadingHTTPServer((bind, 47443), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        tls.socket = context.wrap_socket(tls.socket, server_side=True)
        servers.append(tls)
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("upstream ready", flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
