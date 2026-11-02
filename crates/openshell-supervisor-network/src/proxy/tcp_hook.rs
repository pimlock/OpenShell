// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TCP connection hooks at the proxy's upstream dial sites.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use miette::Result;
use openshell_core::proto::TcpInspection;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, NetworkActivityBuilder, SeverityId, StatusId,
    ocsf_emit,
};
use openshell_supervisor_middleware::{TcpHookAdmission, TcpHookDenial, TcpHookRequest};

use crate::l7::middleware::{middleware_network_input, middleware_request_context};
use crate::l7::relay::L7EvalContext;
use crate::opa::OpaEngine;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Run the preflight of every TCP stage matching this admitted connection.
/// Any failure denies it: TCP hooks always fail closed.
pub(super) async fn admit(
    opa_engine: &OpaEngine,
    ctx: &L7EvalContext,
    inspection: TcpInspection,
) -> TcpHookAdmission {
    match try_admit(opa_engine, ctx, inspection).await {
        Ok(admission) => admission,
        Err(error) => {
            tracing::warn!(host = %ctx.host, port = ctx.port, error = %error, "TCP middleware preflight failed");
            TcpHookAdmission::Deny(TcpHookDenial {
                middleware: "-".to_string(),
                reason_code: "middleware_failure".to_string(),
            })
        }
    }
}

async fn try_admit(
    opa_engine: &OpaEngine,
    ctx: &L7EvalContext,
    inspection: TcpInspection,
) -> Result<TcpHookAdmission> {
    let (chain, _generation) =
        opa_engine.query_middleware_chain_with_generation(&middleware_network_input(ctx))?;
    let runner = opa_engine.middleware_runner()?;
    let connection_id = format!("tcp-{}", NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed));
    let host = ctx.host.clone();
    let port = ctx.port;
    let policy = ctx.policy_name.clone();
    let request = TcpHookRequest {
        host: ctx.host.clone(),
        port: ctx.port,
        inspection,
        policy_keys: if ctx.policy_name.is_empty() {
            Vec::new()
        } else {
            vec![ctx.policy_name.clone()]
        },
        context: middleware_request_context(ctx, &connection_id),
        on_close: Some(Arc::new(
            move |middleware, reason_code, bytes_out, bytes_in| {
                emit_close(
                    &host,
                    port,
                    &policy,
                    middleware,
                    reason_code,
                    bytes_out,
                    bytes_in,
                );
            },
        )),
    };
    runner.open_tcp_hooks(&chain, request).await
}

/// OCSF event for a connection a TCP stage denied at preflight.
pub(super) fn emit_deny(ctx: &L7EvalContext, denial: &TcpHookDenial) {
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&denial.middleware, "tcp-middleware")
        .message(format!(
            "TCP middleware denied {}:{} [middleware:{} reason:{}]",
            ctx.host, ctx.port, denial.middleware, denial.reason_code
        ))
        .status_detail(&denial.reason_code)
        .build();
    ocsf_emit!(event);
}

fn emit_close(
    host: &str,
    port: u16,
    policy: &str,
    middleware: &str,
    reason_code: &str,
    bytes_out: u64,
    bytes_in: u64,
) {
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Close)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(host, port))
        .firewall_rule(middleware, "tcp-middleware")
        .message(format!(
            "TCP middleware closed {host}:{port} [middleware:{middleware} reason:{reason_code} policy:{policy} bytes_out:{bytes_out} bytes_in:{bytes_in}]"
        ))
        .status_detail(reason_code)
        .build();
    ocsf_emit!(event);
}
