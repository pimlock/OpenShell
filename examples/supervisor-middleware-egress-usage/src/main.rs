// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example OpenShell TCP middleware: egress usage.
//!
//! Binds `TCP_CONNECTION` at `PRE_CONNECT` (`TcpHooks.EvaluateConnection`)
//! and selects STATS mode for every connection. It sums upstream bytes into a
//! sliding window per sandbox and network policy key. When a window passes
//! `--max-bytes`, it closes that key's open connections and denies new ones
//! for `--block-for`.

mod usage;

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use openshell_core::extension_protocol::{
    ExtensionFamily, tcp_hooks_middleware_metadata, validate_gateway_metadata,
};
use openshell_core::middleware::{TcpHookResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::middleware::v1::tcp_hooks_server::{TcpHooks, TcpHooksServer};
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding, MiddlewareDescribeRequest,
    MiddlewareManifest, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, TcpHookEvent,
    ValidateConfigRequest, ValidateConfigResponse, WebSocketSessionEvent,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::usage::{Direction, Limits, Usage};

const MANIFEST_NAME: &str = "example/egress-usage";

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell egress-usage TCP middleware")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50061")]
    bind: SocketAddr,
    /// Bytes allowed per window per sandbox and policy key, such as 20MB.
    #[arg(long, default_value = "20MB", value_parser = parse_bytes)]
    max_bytes: u64,
    /// Sliding window length, such as 60s.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    window: Duration,
    /// Stats interval requested from OpenShell, such as 5s.
    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    interval: Duration,
    /// How long a tripped key stays blocked, such as 300s.
    #[arg(long, default_value = "300s", value_parser = parse_duration)]
    block_for: Duration,
    /// Which bytes count toward the window.
    #[arg(long, value_enum, default_value_t = Direction::Both)]
    direction: Direction,
}

fn parse_bytes(value: &str) -> Result<u64, String> {
    let upper = value.trim().to_ascii_uppercase();
    let (digits, multiplier) = [
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("KB", 1_000),
        ("B", 1),
    ]
    .iter()
    .find_map(|(suffix, multiplier)| {
        upper
            .strip_suffix(suffix)
            .map(|digits| (digits.trim().to_string(), *multiplier))
    })
    .unwrap_or((upper.clone(), 1));
    digits
        .parse::<u64>()
        .map(|value| value * multiplier)
        .map_err(|_| format!("invalid byte size '{value}'"))
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (digits, unit) = value.split_at(
        value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(value.len()),
    );
    let number: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration '{value}'"))?;
    match unit {
        "" | "s" => Ok(Duration::from_secs(number)),
        "ms" => Ok(Duration::from_millis(number)),
        "m" => Ok(Duration::from_secs(number * 60)),
        _ => Err(format!("invalid duration '{value}', use ms, s, or m")),
    }
}

#[derive(Clone)]
struct EgressUsage {
    usage: Usage,
}

#[tonic::async_trait]
impl SupervisorMiddleware for EgressUsage {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let manifest = MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::TcpConnection as i32,
                phase: SupervisorMiddlewarePhase::PreConnect as i32,
                ..Default::default()
            }],
            expected_audience: String::new(),
            extension: Some(tcp_hooks_middleware_metadata(
                MANIFEST_NAME,
                openshell_core::VERSION,
            )),
        };
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            MANIFEST_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        _request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        // Thresholds come from flags; any policy config is accepted.
        Ok(Response::new(ValidateConfigResponse {
            valid: true,
            reason: String::new(),
        }))
    }

    async fn evaluate_http_request(
        &self,
        _request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Err(Status::unimplemented(
            "egress usage implements TCP hooks only",
        ))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented(
            "egress usage implements TCP hooks only",
        ))
    }
}

#[tonic::async_trait]
impl TcpHooks for EgressUsage {
    type EvaluateConnectionStream = TcpHookResultStream;

    async fn evaluate_connection(
        &self,
        request: Request<tonic::Streaming<TcpHookEvent>>,
    ) -> Result<Response<Self::EvaluateConnectionStream>, Status> {
        Ok(Response::new(
            self.usage.connection_stream(request.into_inner()),
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let limits = Limits {
        max_bytes: cli.max_bytes,
        window: cli.window,
        interval: cli.interval,
        block_for: cli.block_for,
        direction: cli.direction,
    };
    println!(
        "serving {MANIFEST_NAME} on http://{} max_bytes={} window={:?} interval={:?} block_for={:?} direction={:?}",
        cli.bind,
        limits.max_bytes,
        limits.window,
        limits.interval,
        limits.block_for,
        limits.direction
    );
    let service = EgressUsage {
        usage: Usage::new(limits),
    };
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(service.clone()))
        .add_service(TcpHooksServer::new(service))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes_and_durations() {
        assert_eq!(parse_bytes("20MB").unwrap(), 20_000_000);
        assert_eq!(parse_bytes("512").unwrap(), 512);
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn example_policy_is_valid() {
        let policy = openshell_policy::parse_sandbox_policy(include_str!("../policy.yaml"))
            .expect("example policy must parse");
        openshell_policy::validate_sandbox_policy(&policy).expect("example policy must be valid");
    }
}
