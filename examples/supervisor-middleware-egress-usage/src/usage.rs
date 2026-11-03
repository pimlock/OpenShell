// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sliding egress windows per sandbox and policy key.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openshell_core::middleware::TcpHookResultStream;
use openshell_core::proto::{
    MiddlewareDiagnostics, TcpClose, TcpHookEvent, TcpHookResult, TcpInspect, TcpPreflight,
    TcpPreflightResult, TcpStatsMode, tcp_hook_event, tcp_hook_result, tcp_inspect,
    tcp_preflight_result,
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use crate::config::Config;

/// Reason code sent with every close and deny.
pub const REASON_CODE: &str = "egress_budget_exceeded";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Direction {
    /// bytes_in plus bytes_out.
    Both,
    /// bytes_in only (downloads).
    In,
    /// bytes_out only (uploads).
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub window: Duration,
    pub interval: Duration,
    pub block_for: Duration,
    pub direction: Direction,
}

/// Sandbox id and network policy key.
type Key = (String, String);

#[derive(Default)]
struct Window {
    samples: VecDeque<(Instant, u64)>,
    total: u64,
}

impl Window {
    fn add(&mut self, now: Instant, bytes: u64, window: Duration) -> u64 {
        while let Some(&(at, bytes)) = self.samples.front() {
            if now.duration_since(at) <= window {
                break;
            }
            self.samples.pop_front();
            self.total -= bytes;
        }
        if bytes > 0 {
            self.samples.push_back((now, bytes));
            self.total += bytes;
        }
        self.total
    }
}

type ResultSender = mpsc::Sender<Result<TcpHookResult, Status>>;

#[derive(Default)]
struct State {
    windows: HashMap<Key, Window>,
    blocked_until: HashMap<Key, Instant>,
    open: HashMap<Key, HashMap<u64, ResultSender>>,
}

#[derive(Clone)]
pub struct Usage {
    /// Flag values, used where the policy config leaves a field unset.
    defaults: Limits,
    state: Arc<Mutex<State>>,
    next_id: Arc<AtomicU64>,
}

fn close_result() -> TcpHookResult {
    TcpHookResult {
        result: Some(tcp_hook_result::Result::Close(TcpClose {
            diagnostics: Some(MiddlewareDiagnostics {
                reason: "sandbox egress over budget".into(),
                reason_code: REASON_CODE.into(),
                ..Default::default()
            }),
        })),
    }
}

fn key_of(preflight: &TcpPreflight) -> Key {
    let sandbox = preflight
        .context
        .as_ref()
        .map(|context| context.sandbox_id.clone())
        .unwrap_or_default();
    let policy = preflight
        .policy_keys
        .first()
        .cloned()
        .unwrap_or_else(|| preflight.endpoint_id.clone());
    (sandbox, policy)
}

impl Usage {
    pub fn new(defaults: Limits) -> Self {
        Self {
            defaults,
            state: Arc::default(),
            next_id: Arc::default(),
        }
    }

    /// Parses a policy config, filling unset fields from the flags.
    pub fn config(&self, config: Option<&prost_types::Struct>) -> Result<Config, String> {
        Config::parse(config, self.defaults)
    }
}

fn counted(limits: &Limits, bytes_out: u64, bytes_in: u64) -> u64 {
    match limits.direction {
        Direction::Both => bytes_out + bytes_in,
        Direction::In => bytes_in,
        Direction::Out => bytes_out,
    }
}

impl Usage {
    pub fn connection_stream(
        &self,
        mut events: tonic::Streaming<TcpHookEvent>,
    ) -> TcpHookResultStream {
        let (tx, rx) = mpsc::channel(4);
        let usage = self.clone();
        tokio::spawn(async move {
            let Some(Ok(TcpHookEvent {
                event: Some(tcp_hook_event::Event::Preflight(preflight)),
            })) = events.next().await
            else {
                let _ = tx
                    .send(Err(Status::invalid_argument(
                        "first event must be preflight",
                    )))
                    .await;
                return;
            };
            let key = key_of(&preflight);
            // The policy config is read per connection, so a policy update
            // applies to connections opened after it loads.
            let limits = match usage.config(preflight.config.as_ref()) {
                Ok(config) => config.limits_for(&key.1),
                Err(error) => {
                    let _ = tx.send(Err(Status::invalid_argument(error))).await;
                    return;
                }
            };
            let id = usage.next_id.fetch_add(1, Ordering::Relaxed);
            let blocked = {
                let mut state = usage.state.lock().unwrap();
                let now = Instant::now();
                let blocked = state
                    .blocked_until
                    .get(&key)
                    .is_some_and(|until| *until > now);
                if !blocked {
                    state
                        .open
                        .entry(key.clone())
                        .or_default()
                        .insert(id, tx.clone());
                }
                blocked
            };
            if blocked {
                println!(
                    "deny sandbox={} policy={} host={}:{} reason={REASON_CODE}",
                    key.0, key.1, preflight.host, preflight.port
                );
                let _ = tx.send(Ok(close_result())).await;
                return;
            }
            let interval = prost_types::Duration::try_from(limits.interval).ok();
            let _ = tx
                .send(Ok(TcpHookResult {
                    result: Some(tcp_hook_result::Result::PreflightResult(
                        TcpPreflightResult {
                            decision: Some(tcp_preflight_result::Decision::Inspect(TcpInspect {
                                mode: Some(tcp_inspect::Mode::Stats(TcpStatsMode { interval })),
                            })),
                            diagnostics: None,
                        },
                    )),
                }))
                .await;
            let mut last = 0_u64;
            while let Some(Ok(event)) = events.next().await {
                let (bytes_out, bytes_in, end) = match event.event {
                    Some(tcp_hook_event::Event::Stats(stats)) => {
                        (stats.bytes_out, stats.bytes_in, false)
                    }
                    Some(tcp_hook_event::Event::End(end)) => (end.bytes_out, end.bytes_in, true),
                    _ => continue,
                };
                let counted = counted(&limits, bytes_out, bytes_in);
                let delta = counted.saturating_sub(last);
                last = counted;
                usage.record(&key, &preflight, &limits, delta);
                if end {
                    break;
                }
            }
            let mut state = usage.state.lock().unwrap();
            if let Some(open) = state.open.get_mut(&key) {
                open.remove(&id);
            }
        });
        Box::pin(ReceiverStream::new(rx))
    }

    /// Add `delta` to the key's window and trip it when over the limit.
    fn record(&self, key: &Key, preflight: &TcpPreflight, limits: &Limits, delta: u64) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let total = state
            .windows
            .entry(key.clone())
            .or_default()
            .add(now, delta, limits.window);
        let already_blocked = state
            .blocked_until
            .get(key)
            .is_some_and(|until| *until > now);
        if total <= limits.max_bytes || already_blocked {
            return;
        }
        state
            .blocked_until
            .insert(key.clone(), now + limits.block_for);
        let open = state.open.remove(key).unwrap_or_default();
        println!(
            "TRIP sandbox={} policy={} host={}:{} window_bytes={total} max_bytes={} over_by={} closing={} block_for={:?}",
            key.0,
            key.1,
            preflight.host,
            preflight.port,
            limits.max_bytes,
            total - limits.max_bytes,
            open.len(),
            limits.block_for,
        );
        for sender in open.into_values() {
            // Never block the lock holder: a full result channel already has
            // a pending result, and the connection is denied on its next one.
            let _ = sender.try_send(Ok(close_result()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_expires_old_samples() {
        let mut window = Window::default();
        let start = Instant::now();
        assert_eq!(window.add(start, 10, Duration::from_secs(60)), 10);
        assert_eq!(
            window.add(start + Duration::from_secs(30), 5, Duration::from_secs(60)),
            15
        );
        assert_eq!(
            window.add(start + Duration::from_secs(61), 1, Duration::from_secs(60)),
            6
        );
    }
}
