// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TCP connection hooks (`TcpHooks.EvaluateConnection`).
//!
//! One stream per admitted upstream connection and stage. The preflight runs
//! before the upstream is dialed and can deny the connection. A stage that
//! selects STATS receives cumulative upstream byte totals at its interval. Any
//! stage can close the connection at any time. TCP hooks always fail closed.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::StreamExt;
use futures::task::AtomicWaker;
use miette::Result;
use openshell_core::proto::{
    MiddlewareSessionEndReason, RequestContext, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, TcpEnd, TcpHookEvent, TcpHookResult, TcpInspection, TcpLimits,
    TcpMode, TcpPreflight, TcpStats, tcp_hook_event, tcp_hook_result, tcp_inspect,
    tcp_preflight_result,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

use crate::{ChainEntry, ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_REASON_CODE_BYTES};

/// Shortest stats interval a stage may select.
pub const MIN_TCP_STATS_INTERVAL: Duration = Duration::from_secs(1);
/// Longest stats interval a stage may select.
pub const MAX_TCP_STATS_INTERVAL: Duration = Duration::from_mins(1);
/// Process-wide cap on concurrently observed connections. Spike: one shared
/// cap, not a budget per service.
pub const MAX_TCP_HOOK_CONNECTIONS: usize = 4096;

static TCP_HOOK_CONNECTIONS: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(MAX_TCP_HOOK_CONNECTIONS)));

/// Upstream byte counters and the close switch for one connection.
#[derive(Debug)]
pub struct TcpConnectionMeter {
    bytes_out: AtomicU64,
    bytes_in: AtomicU64,
    closed: AtomicBool,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
    started: Instant,
}

impl Default for TcpConnectionMeter {
    fn default() -> Self {
        Self {
            bytes_out: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
            started: Instant::now(),
        }
    }
}

impl TcpConnectionMeter {
    /// Bytes written to and read from the upstream so far.
    #[must_use]
    pub fn totals(&self) -> (u64, u64) {
        (
            self.bytes_out.load(Ordering::Relaxed),
            self.bytes_in.load(Ordering::Relaxed),
        )
    }

    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Abort the connection: pending and later upstream reads and writes fail.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.read_waker.wake();
        self.write_waker.wake();
    }
}

fn aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "connection closed by TCP middleware",
    )
}

/// Upstream stream wrapper that counts bytes and honors the meter's close.
pub struct MeteredStream<S> {
    inner: S,
    meter: Arc<TcpConnectionMeter>,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, meter: Arc<TcpConnectionMeter>) -> Self {
        Self { inner, meter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.meter.read_waker.register(cx.waker());
        if this.meter.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(()))) {
            let read = buf.filled().len().saturating_sub(before);
            this.meter
                .bytes_in
                .fetch_add(read as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.meter.write_waker.register(cx.waker());
        if this.meter.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            this.meter
                .bytes_out
                .fetch_add(*written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.meter.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Called once when a stage closes an open connection: middleware name,
/// reason code, bytes out, bytes in.
pub type TcpCloseObserver = Arc<dyn Fn(&str, &str, u64, u64) + Send + Sync>;

/// One admitted upstream connection to evaluate.
pub struct TcpHookRequest {
    pub host: String,
    pub port: u16,
    pub inspection: TcpInspection,
    pub policy_keys: Vec<String>,
    pub context: RequestContext,
    pub on_close: Option<TcpCloseObserver>,
}

/// A stage denied the connection at preflight, or failed.
#[derive(Debug, Clone)]
pub struct TcpHookDenial {
    pub middleware: String,
    /// Stable reason code from the stage, or an `OpenShell` failure code.
    pub reason_code: String,
}

pub enum TcpHookAdmission {
    /// Relay through [`TcpHookSession::wrap`].
    Allow(TcpHookSession),
    Deny(TcpHookDenial),
}

struct StageHandle {
    end: Option<oneshot::Sender<MiddlewareSessionEndReason>>,
}

/// Observed connection. Dropping it ends every stage stream with
/// `NORMAL`; [`TcpHookSession::finish`] supplies another reason.
pub struct TcpHookSession {
    meter: Arc<TcpConnectionMeter>,
    stages: Vec<StageHandle>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl TcpHookSession {
    #[must_use]
    pub fn meter(&self) -> &Arc<TcpConnectionMeter> {
        &self.meter
    }

    /// True when no stage observes the connection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// Wrap the upstream stream so its bytes are counted and a stage can
    /// close it.
    pub fn wrap<S>(&self, upstream: S) -> MeteredStream<S> {
        MeteredStream::new(upstream, Arc::clone(&self.meter))
    }

    /// End every stage stream with `reason`.
    pub fn finish(mut self, reason: MiddlewareSessionEndReason) {
        self.end_all(reason);
    }

    fn end_all(&mut self, reason: MiddlewareSessionEndReason) {
        for stage in &mut self.stages {
            if let Some(end) = stage.end.take() {
                let _ = end.send(reason);
            }
        }
    }
}

impl Drop for TcpHookSession {
    fn drop(&mut self) {
        let reason = if self.meter.is_closed() {
            MiddlewareSessionEndReason::MiddlewareDenial
        } else {
            MiddlewareSessionEndReason::Normal
        };
        self.end_all(reason);
    }
}

fn duration_proto(duration: Duration) -> prost_types::Duration {
    prost_types::Duration::try_from(duration).unwrap_or_default()
}

/// Accept the stage's code when it is a stable reason code, else a generic one.
fn stage_reason_code(code: &str, fallback: &str) -> String {
    if !code.is_empty()
        && code.len() <= MAX_MIDDLEWARE_REASON_CODE_BYTES
        && crate::is_stable_reason_code(code)
    {
        code.to_string()
    } else {
        fallback.to_string()
    }
}

enum StagePreflight {
    Continue,
    Stats(Duration),
    Close(String),
}

impl ChainRunner {
    /// Run the TCP connection preflight of every matching stage, in chain
    /// order. The first deny or failure denies the connection.
    pub async fn open_tcp_hooks(
        &self,
        entries: &[ChainEntry],
        request: TcpHookRequest,
    ) -> Result<TcpHookAdmission> {
        if entries.is_empty() {
            return Ok(TcpHookAdmission::Allow(TcpHookSession {
                meter: Arc::new(TcpConnectionMeter::default()),
                stages: Vec::new(),
                _permit: None,
            }));
        }
        let described = self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::TcpConnection,
                SupervisorMiddlewarePhase::PreConnect,
            )
            .await?
            .entries;
        let meter = Arc::new(TcpConnectionMeter::default());
        if described.is_empty() {
            return Ok(TcpHookAdmission::Allow(TcpHookSession {
                meter,
                stages: Vec::new(),
                _permit: None,
            }));
        }
        let Ok(permit) = Arc::clone(&TCP_HOOK_CONNECTIONS).try_acquire_owned() else {
            return Ok(TcpHookAdmission::Deny(TcpHookDenial {
                middleware: described[0].entry.name.clone(),
                reason_code: "middleware_capacity_exhausted".to_string(),
            }));
        };
        let mut session = TcpHookSession {
            meter,
            stages: Vec::with_capacity(described.len()),
            _permit: Some(permit),
        };
        let request = Arc::new(request);
        for entry in &described {
            match open_stage(entry, &request, &session.meter).await {
                Ok(stage) => session.stages.push(stage),
                Err(reason_code) => {
                    session.end_all(MiddlewareSessionEndReason::MiddlewareDenial);
                    return Ok(TcpHookAdmission::Deny(TcpHookDenial {
                        middleware: entry.entry.name.clone(),
                        reason_code,
                    }));
                }
            }
        }
        Ok(TcpHookAdmission::Allow(session))
    }
}

async fn open_stage(
    described: &DescribedChainEntry,
    request: &Arc<TcpHookRequest>,
    meter: &Arc<TcpConnectionMeter>,
) -> std::result::Result<StageHandle, String> {
    let Some(state) = described.service.as_ref() else {
        return Err("middleware_unavailable".to_string());
    };
    let (tx, rx) = mpsc::channel::<TcpHookEvent>(4);
    let preflight = TcpPreflight {
        host: request.host.clone(),
        port: u32::from(request.port),
        sni: String::new(),
        inspection: request.inspection as i32,
        policy_keys: request.policy_keys.clone(),
        endpoint_id: format!("{}:{}", request.host, request.port),
        context: Some(request.context.clone()),
        middleware_name: described.entry.name.clone(),
        config: Some(described.entry.config.clone()),
        permitted_modes: vec![TcpMode::Stats as i32],
        limits: Some(TcpLimits {
            min_stats_interval: Some(duration_proto(MIN_TCP_STATS_INTERVAL)),
            max_stats_interval: Some(duration_proto(MAX_TCP_STATS_INTERVAL)),
        }),
        phase: SupervisorMiddlewarePhase::PreConnect as i32,
    };
    tx.send(TcpHookEvent {
        event: Some(tcp_hook_event::Event::Preflight(preflight)),
    })
    .await
    .map_err(|_| "middleware_failure".to_string())?;

    let timeout = described.timeout;
    let mut results = tokio::time::timeout(timeout, state.service.open_tcp_connection_hook(rx))
        .await
        .map_err(|_| "middleware_timeout".to_string())?
        .map_err(|status| {
            tracing::warn!(
                middleware = %described.entry.name,
                error = %status,
                "TCP middleware stream failed to open"
            );
            "middleware_failure".to_string()
        })?;
    let first = tokio::time::timeout(timeout, results.next())
        .await
        .map_err(|_| "middleware_timeout".to_string())?;
    let decision = match first {
        Some(Ok(TcpHookResult {
            result: Some(tcp_hook_result::Result::PreflightResult(result)),
        })) => match result.decision {
            Some(tcp_preflight_result::Decision::ContinueWithoutInspection(_)) => {
                StagePreflight::Continue
            }
            Some(tcp_preflight_result::Decision::Inspect(inspect)) => match inspect.mode {
                Some(tcp_inspect::Mode::Stats(mode)) => {
                    let interval = mode
                        .interval
                        .as_ref()
                        .and_then(|value| openshell_core::time::duration_to_std(value).ok())
                        .unwrap_or(MIN_TCP_STATS_INTERVAL)
                        .clamp(MIN_TCP_STATS_INTERVAL, MAX_TCP_STATS_INTERVAL);
                    StagePreflight::Stats(interval)
                }
                None => return Err("middleware_protocol_error".to_string()),
            },
            None => return Err("middleware_protocol_error".to_string()),
        },
        Some(Ok(TcpHookResult {
            result: Some(tcp_hook_result::Result::Close(close)),
        })) => StagePreflight::Close(stage_reason_code(
            &close.diagnostics.unwrap_or_default().reason_code,
            "middleware_denied",
        )),
        Some(Ok(_)) => return Err("middleware_protocol_error".to_string()),
        Some(Err(status)) => {
            tracing::warn!(
                middleware = %described.entry.name,
                error = %status,
                "TCP middleware preflight failed"
            );
            return Err("middleware_failure".to_string());
        }
        None => return Err("middleware_failure".to_string()),
    };
    let interval = match decision {
        StagePreflight::Close(reason_code) => {
            let _ = tx.try_send(end_event(
                meter,
                MiddlewareSessionEndReason::MiddlewareDenial,
            ));
            return Err(reason_code);
        }
        StagePreflight::Continue => None,
        StagePreflight::Stats(interval) => Some(interval),
    };
    let (end_tx, end_rx) = oneshot::channel();
    tokio::spawn(run_stage(
        described.entry.name.clone(),
        Arc::clone(request),
        Arc::clone(meter),
        tx,
        results,
        interval,
        end_rx,
    ));
    Ok(StageHandle { end: Some(end_tx) })
}

fn end_event(meter: &TcpConnectionMeter, reason: MiddlewareSessionEndReason) -> TcpHookEvent {
    let (bytes_out, bytes_in) = meter.totals();
    TcpHookEvent {
        event: Some(tcp_hook_event::Event::End(TcpEnd {
            bytes_out,
            bytes_in,
            duration: Some(duration_proto(meter.elapsed())),
            reason: reason as i32,
        })),
    }
}

/// Drive one stage after preflight: send stats when totals moved, apply a
/// close, and send the end. A broken stream closes the connection.
async fn run_stage(
    middleware: String,
    request: Arc<TcpHookRequest>,
    meter: Arc<TcpConnectionMeter>,
    tx: mpsc::Sender<TcpHookEvent>,
    mut results: openshell_core::middleware::TcpHookResultStream,
    interval: Option<Duration>,
    mut end_rx: oneshot::Receiver<MiddlewareSessionEndReason>,
) {
    let mut ticker = interval.map(|interval| {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker
    });
    let mut last = (0_u64, 0_u64);
    let mut results_open = true;
    let reason = loop {
        tokio::select! {
            reason = &mut end_rx => {
                break reason.unwrap_or(MiddlewareSessionEndReason::Cancellation);
            }
            () = async {
                match ticker.as_mut() {
                    Some(ticker) => { ticker.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                let totals = meter.totals();
                if totals != last {
                    last = totals;
                    // Latest value wins: a full channel skips this update and
                    // the next tick sends newer cumulative totals.
                    let _ = tx.try_send(TcpHookEvent {
                        event: Some(tcp_hook_event::Event::Stats(TcpStats {
                            bytes_out: totals.0,
                            bytes_in: totals.1,
                            elapsed: Some(duration_proto(meter.elapsed())),
                        })),
                    });
                }
            }
            result = results.next(), if results_open => {
                match result {
                    Some(Ok(TcpHookResult { result: Some(tcp_hook_result::Result::Close(close)) })) => {
                        let reason_code = stage_reason_code(
                            &close.diagnostics.unwrap_or_default().reason_code,
                            "middleware_closed",
                        );
                        close_connection(&middleware, &request, &meter, &reason_code);
                    }
                    Some(Ok(_)) => {
                        close_connection(&middleware, &request, &meter, "middleware_protocol_error");
                    }
                    Some(Err(status)) => {
                        tracing::warn!(middleware = %middleware, error = %status, "TCP middleware stream failed");
                        close_connection(&middleware, &request, &meter, "middleware_failure");
                        results_open = false;
                    }
                    None => {
                        // The stage ended its response stream. Fail closed.
                        close_connection(&middleware, &request, &meter, "middleware_failure");
                        results_open = false;
                    }
                }
            }
        }
    };
    let _ = tx.send(end_event(&meter, reason)).await;
    // Dropping the response stream cancels the RPC, which can discard the
    // queued end before it is flushed. Half-close the request side and let
    // the stage finish its responses, so short connections that end before
    // their first stats tick still report their totals.
    drop(tx);
    if results_open {
        let _ = tokio::time::timeout(TCP_END_DRAIN_TIMEOUT, async {
            while let Some(Ok(_)) = results.next().await {}
        })
        .await;
    }
}

/// How long a stage may take to finish its response stream after the end.
const TCP_END_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

fn close_connection(
    middleware: &str,
    request: &TcpHookRequest,
    meter: &TcpConnectionMeter,
    reason_code: &str,
) {
    if meter.is_closed() {
        return;
    }
    meter.close();
    let (bytes_out, bytes_in) = meter.totals();
    if let Some(on_close) = request.on_close.as_ref() {
        on_close(middleware, reason_code, bytes_out, bytes_in);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn metered_stream_counts_bytes_and_close_aborts_pending_read() {
        let (client, mut server) = tokio::io::duplex(1024);
        let meter = Arc::new(TcpConnectionMeter::default());
        let mut upstream = MeteredStream::new(client, Arc::clone(&meter));

        upstream.write_all(b"hello").await.unwrap();
        server.write_all(b"world!").await.unwrap();
        let mut buf = [0_u8; 6];
        upstream.read_exact(&mut buf).await.unwrap();
        assert_eq!(meter.totals(), (5, 6));

        let pending = tokio::spawn(async move {
            let mut buf = [0_u8; 1];
            upstream.read(&mut buf).await
        });
        tokio::task::yield_now().await;
        meter.close();
        let error = pending.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
}
