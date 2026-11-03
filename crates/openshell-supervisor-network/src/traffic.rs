// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-connection egress byte accounting reported as OCSF Network Activity.
//!
//! [`track`] wraps the upstream side of a relay in a [`CountingStream`] that
//! adds every byte read from or written to the upstream socket to shared
//! atomics. A reporter thread, never the relay task, reads them:
//!
//! - every connection gets one `Close` event with its totals
//!   (`cumulative_traffic`), lifetime, and the bytes not yet reported
//!   (`traffic`);
//! - when `ocsf_traffic_interval_secs` is non-zero, connections that moved
//!   bytes also get a `Traffic` event per interval with that interval's
//!   amounts.
//!
//! Summing `traffic` over a connection's events gives its totals. Events use
//! [`openshell_ocsf::OCSF_TRAFFIC_TARGET`], so only the JSONL file and OTLP
//! export receive them.

use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Once, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use openshell_ocsf::{
    ActionId, ActivityId, ConnectionInfo, ContextRef, DispositionId, Endpoint,
    NetworkActivityBuilder, NetworkTraffic, Process, SeverityId, StatusId, emit_ocsf_traffic_event,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Smallest accepted interval. Shorter values are raised to this.
pub const MIN_INTERVAL_SECS: u64 = 5;
/// How often the reporter checks for closed connections and due intervals.
const TICK: Duration = Duration::from_secs(1);

/// Interim report interval in seconds; 0 disables `Traffic` events.
static INTERVAL_SECS: AtomicU64 = AtomicU64::new(0);
static REGISTRY: LazyLock<Mutex<Vec<Arc<Connection>>>> = LazyLock::new(Mutex::default);
static REPORTER: Once = Once::new();

/// Apply the `ocsf_traffic_interval_secs` setting. Returns the effective value.
pub fn set_interval_secs(requested: u64) -> u64 {
    let effective = if requested == 0 {
        0
    } else {
        requested.max(MIN_INTERVAL_SECS)
    };
    INTERVAL_SECS.store(effective, Ordering::Relaxed);
    effective
}

/// What a tracked connection is attributed to.
#[derive(Debug, Clone)]
pub struct ConnectionMeta {
    pub host: String,
    pub port: u16,
    /// Policy key that authorized the connection, or `-`.
    pub policy: String,
    pub binary: String,
    pub pid: Option<u32>,
}

struct Connection {
    uid: String,
    meta: ConnectionMeta,
    ctx: ContextRef<'static>,
    started_ms: i64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// 0 while open.
    closed_ms: AtomicI64,
    // Reporter-owned progress.
    reported_in: AtomicU64,
    reported_out: AtomicU64,
    window_start_ms: AtomicI64,
}

/// Count bytes moved through `inner` and report them for `meta`.
pub fn track<S>(inner: S, meta: ConnectionMeta) -> CountingStream<S> {
    REPORTER.call_once(spawn_reporter);
    let now = now_ms();
    let connection = Arc::new(Connection {
        uid: format!("conn-{}", uuid::Uuid::new_v4()),
        meta,
        ctx: openshell_ocsf::ctx::ctx(),
        started_ms: now,
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
        closed_ms: AtomicI64::new(0),
        reported_in: AtomicU64::new(0),
        reported_out: AtomicU64::new(0),
        window_start_ms: AtomicI64::new(now),
    });
    REGISTRY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Arc::clone(&connection));
    CountingStream { inner, connection }
}

/// Upstream stream wrapper that counts bytes in each direction.
pub struct CountingStream<S> {
    inner: S,
    connection: Arc<Connection>,
}

impl<S> Drop for CountingStream<S> {
    fn drop(&mut self) {
        self.connection.closed_ms.store(now_ms(), Ordering::Release);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) {
            let read = (buf.filled().len() - before) as u64;
            this.connection.bytes_in.fetch_add(read, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = poll {
            this.connection
                .bytes_out
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(written)) = poll {
            this.connection
                .bytes_out
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn spawn_reporter() {
    let spawned = std::thread::Builder::new()
        .name("openshell-traffic".to_string())
        .spawn(|| {
            let mut last_interval_ms = now_ms();
            loop {
                std::thread::sleep(TICK);
                let now = now_ms();
                let interval = INTERVAL_SECS.load(Ordering::Relaxed);
                let interval_due = interval > 0
                    && now - last_interval_ms >= i64::try_from(interval * 1000).unwrap_or(i64::MAX);
                if interval_due {
                    last_interval_ms = now;
                }
                report(now, interval_due);
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "traffic reporter could not start; no traffic events");
    }
}

/// Emit Close events for closed connections and, when `interval_due`,
/// Traffic events for open connections that moved bytes.
fn report(now: i64, interval_due: bool) {
    let (closed, open): (Vec<_>, Vec<_>) = {
        let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = std::mem::take(&mut *registry);
        let (closed, open): (Vec<_>, Vec<_>) = snapshot
            .into_iter()
            .partition(|c| c.closed_ms.load(Ordering::Acquire) != 0);
        registry.extend(open.iter().cloned());
        (closed, open)
    };
    if interval_due {
        for connection in &open {
            if let Some(delta) = take_delta(connection) {
                let start = connection.window_start_ms.swap(now, Ordering::Relaxed);
                emit(connection, ActivityId::Traffic, delta, None, start, now);
            }
        }
    }
    for connection in &closed {
        let delta = take_delta(connection).unwrap_or_default();
        let closed_ms = connection.closed_ms.load(Ordering::Acquire);
        let total = NetworkTraffic::new(
            connection.bytes_in.load(Ordering::Relaxed),
            connection.bytes_out.load(Ordering::Relaxed),
        );
        emit(
            connection,
            ActivityId::Close,
            delta,
            Some(total),
            connection.started_ms,
            closed_ms,
        );
    }
}

/// Bytes not yet reported, or `None` when nothing moved.
fn take_delta(connection: &Connection) -> Option<NetworkTraffic> {
    let bytes_in = connection.bytes_in.load(Ordering::Relaxed);
    let bytes_out = connection.bytes_out.load(Ordering::Relaxed);
    let prev_in = connection.reported_in.swap(bytes_in, Ordering::Relaxed);
    let prev_out = connection.reported_out.swap(bytes_out, Ordering::Relaxed);
    let delta = NetworkTraffic::new(bytes_in - prev_in, bytes_out - prev_out);
    (delta.bytes > 0).then_some(delta)
}

fn emit(
    connection: &Connection,
    activity: ActivityId,
    delta: NetworkTraffic,
    total: Option<NetworkTraffic>,
    start_ms: i64,
    end_ms: i64,
) {
    let meta = &connection.meta;
    let verb = if total.is_some() { "CLOSE" } else { "TRAFFIC" };
    let mut builder = NetworkActivityBuilder::new(connection.ctx.clone())
        .activity(activity)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(Endpoint::from_domain(&meta.host, meta.port))
        .actor_process(Process::new(&meta.binary, meta.pid.map_or(0, i64::from)))
        .firewall_rule(&meta.policy, "opa")
        .connection_info(ConnectionInfo::new("tcp").with_uid(&connection.uid))
        .traffic(delta)
        .time_window(start_ms, end_ms)
        .message(format!(
            "{verb} {}:{} in={} out={}",
            meta.host, meta.port, delta.bytes_in, delta.bytes_out
        ));
    if let Some(total) = total {
        builder = builder
            .cumulative_traffic(total)
            .duration_ms(end_ms - connection.started_ms);
    }
    emit_ocsf_traffic_event(builder.build());
}

fn now_ms() -> i64 {
    openshell_core::time::now_ms()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counting_stream_counts_both_directions() {
        let (client, mut server) = tokio::io::duplex(1024);
        let mut stream = track(
            client,
            ConnectionMeta {
                host: "artifactory.internal".to_string(),
                port: 443,
                policy: "pkg_proxy".to_string(),
                binary: "/usr/bin/curl".to_string(),
                pid: Some(42),
            },
        );
        stream.write_all(b"hello").await.unwrap();
        server.write_all(b"world!!").await.unwrap();
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.unwrap();
        let connection = Arc::clone(&stream.connection);
        assert_eq!(connection.bytes_out.load(Ordering::Relaxed), 5);
        assert_eq!(connection.bytes_in.load(Ordering::Relaxed), 7);
        assert_eq!(take_delta(&connection), Some(NetworkTraffic::new(7, 5)));
        assert_eq!(take_delta(&connection), None);
        drop(stream);
        assert_ne!(connection.closed_ms.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn interval_is_clamped() {
        assert_eq!(set_interval_secs(0), 0);
        assert_eq!(set_interval_secs(1), MIN_INTERVAL_SECS);
        assert_eq!(set_interval_secs(30), 30);
        set_interval_secs(0);
    }
}
