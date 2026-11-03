// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example external detector for OpenShell egress (spike 01b).
//!
//! Receives OCSF events as OTLP/gRPC log records, from supervisors directly
//! or through a collector, and reacts through the `openshell` CLI:
//!
//! - Volume (D2): bytes per sandbox and policy key over a sliding window,
//!   from Network Activity Traffic (6) and Close (2) events. Each event's
//!   `traffic` is the delta since the connection's previous report, so sums
//!   never double count.
//! - Writers (D1): distinct sandboxes sending HTTP PUT to one host over a
//!   window, from HTTP Activity (4002) events.

mod detect;
mod react;

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use openshell_ocsf::{HttpActivityEvent, HttpMethod, NetworkActivityEvent, OcsfEvent};
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::{
    LogsService, LogsServiceServer,
};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use tonic::codec::CompressionEncoding;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::detect::{DistinctRule, VolumeRule};
use crate::react::{Reaction, Reactor, Trip};

const ACTIVITY_CLOSE: u8 = 2;
const ACTIVITY_TRAFFIC: u8 = 6;
/// OTLP export is at least once; remember this many event uids.
const SEEN_UIDS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Direction {
    /// bytes_in plus bytes_out.
    Both,
    /// bytes_in only (downloads).
    In,
    /// bytes_out only (uploads).
    Out,
}

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell egress-usage detector")]
struct Cli {
    /// OTLP/gRPC listen address.
    #[arg(long, default_value = "127.0.0.1:14317")]
    listen: SocketAddr,
    #[arg(long, value_enum, default_value_t = Reaction::Deny)]
    reaction: Reaction,
    /// `openshell` CLI binary.
    #[arg(long, default_value = "openshell")]
    openshell: String,
    /// Gateway name passed to the CLI as `--gateway`.
    #[arg(long)]
    gateway: Option<String>,
    /// Workspace of the sandboxes (`OPENSHELL_WORKSPACE`).
    #[arg(long)]
    workspace: Option<String>,
    /// Log reactions without calling the CLI.
    #[arg(long)]
    dry_run: bool,
    /// Log every traffic event.
    #[arg(long)]
    verbose: bool,
    /// How long a tripped key or host is ignored, such as 300s.
    #[arg(long, default_value = "300s", value_parser = parse_duration)]
    cooldown: Duration,

    /// Volume: bytes allowed per window per sandbox and policy key, such as 20MB.
    #[arg(long, default_value = "20MB", value_parser = parse_bytes)]
    max_bytes: u64,
    /// Volume: sliding window length, such as 60s.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    window: Duration,
    /// Volume: which bytes count toward the window.
    #[arg(long, value_enum, default_value_t = Direction::Both)]
    direction: Direction,
    /// Volume: only watch these policy keys (repeatable).
    #[arg(long)]
    policy: Vec<String>,

    /// Writers: trip when distinct PUT writers to one host exceed this.
    #[arg(long, default_value_t = 5)]
    max_writers: usize,
    /// Writers: sliding window length, such as 300s.
    #[arg(long, default_value = "300s", value_parser = parse_duration)]
    writers_window: Duration,
    /// Writers: only watch this host.
    #[arg(long)]
    writers_host: Option<String>,
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

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Print `message` with a UTC `HH:MM:SS.mmm` prefix.
fn log(message: &str) {
    let ms = now_ms();
    let day_ms = ms.rem_euclid(86_400_000);
    println!(
        "{:02}:{:02}:{:02}.{:03} {message}",
        day_ms / 3_600_000,
        day_ms / 60_000 % 60,
        day_ms / 1000 % 60,
        day_ms % 1000
    );
}

/// Sandbox name, which the CLI takes, falling back to its id.
fn sandbox_of(event: &OcsfEvent) -> String {
    event
        .base()
        .container
        .as_ref()
        .map(|container| {
            if container.name.is_empty() {
                container.uid.clone().unwrap_or_default()
            } else {
                container.name.clone()
            }
        })
        .unwrap_or_else(|| "-".into())
}

struct State {
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    volume: VolumeRule<(String, String)>,
    writers: DistinctRule<String, String>,
}

impl State {
    /// Whether `uid` was seen before; remembers it otherwise.
    fn duplicate(&mut self, uid: &str) -> bool {
        if !self.seen.insert(uid.to_string()) {
            return true;
        }
        self.seen_order.push_back(uid.to_string());
        if self.seen_order.len() > SEEN_UIDS
            && let Some(oldest) = self.seen_order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        false
    }
}

#[derive(Clone)]
struct Detector {
    cli: Arc<Cli>,
    reactor: Reactor,
    state: Arc<Mutex<State>>,
}

impl Detector {
    fn ingest(&self, event: &OcsfEvent) {
        if let Some(uid) = &event.base().metadata.uid
            && self.state.lock().unwrap().duplicate(uid)
        {
            return;
        }
        match event {
            OcsfEvent::NetworkActivity(network)
                if matches!(network.base.activity_id, ACTIVITY_TRAFFIC | ACTIVITY_CLOSE) =>
            {
                self.on_traffic(event, network);
            }
            OcsfEvent::HttpActivity(http) => self.on_http(event, http),
            _ => {}
        }
    }

    fn on_traffic(&self, event: &OcsfEvent, network: &NetworkActivityEvent) {
        let Some(traffic) = network.traffic.traffic else {
            return;
        };
        let bytes = match self.cli.direction {
            Direction::Both => traffic.bytes,
            Direction::In => traffic.bytes_in,
            Direction::Out => traffic.bytes_out,
        };
        if bytes == 0 {
            return;
        }
        let sandbox = sandbox_of(event);
        let policy = network
            .firewall_rule
            .as_ref()
            .map_or_else(|| "-".to_string(), |rule| rule.name.clone());
        if !self.cli.policy.is_empty() && !self.cli.policy.contains(&policy) {
            return;
        }
        let now = Instant::now();
        let key = (sandbox, policy);
        let Some(total) = self.state.lock().unwrap().volume.record(&key, bytes, now) else {
            if self.cli.verbose {
                log(&format!("traffic {}/{} +{bytes}", key.0, key.1));
            }
            return;
        };
        let event_ms = network.traffic.end_time.unwrap_or(network.base.time);
        log(&format!(
            "VOLUME TRIP sandbox={} policy={} window_bytes={total} > {} in {:?} (event lag {} ms)",
            key.0,
            key.1,
            self.cli.max_bytes,
            self.cli.window,
            now_ms() - event_ms,
        ));
        let (sandbox, policy) = key;
        self.reactor
            .react(Trip::Volume { sandbox, policy }, now, event_ms);
    }

    fn on_http(&self, event: &OcsfEvent, http: &HttpActivityEvent) {
        let Some(request) = &http.http_request else {
            return;
        };
        if request.http_method != HttpMethod::Put {
            return;
        }
        let url = request.url.as_ref();
        let host = url
            .and_then(|url| url.hostname.clone())
            .or_else(|| {
                http.dst_endpoint
                    .as_ref()
                    .and_then(|dst| dst.domain.clone())
            })
            .unwrap_or_else(|| "-".into());
        let port = url
            .and_then(|url| url.port)
            .or_else(|| http.dst_endpoint.as_ref().and_then(|dst| dst.port));
        if self
            .cli
            .writers_host
            .as_ref()
            .is_some_and(|only| *only != host)
        {
            return;
        }
        let sandbox = sandbox_of(event);
        let policy = http
            .firewall_rule
            .as_ref()
            .map_or_else(|| "-".to_string(), |rule| rule.name.clone());
        let now = Instant::now();
        let Some(writers) = self
            .state
            .lock()
            .unwrap()
            .writers
            .record(&host, &sandbox, now)
        else {
            return;
        };
        log(&format!(
            "WRITERS TRIP host={host} distinct_put_writers={} > {} in {:?}: {}",
            writers.len(),
            self.cli.max_writers,
            self.cli.writers_window,
            writers.join(", "),
        ));
        for sandbox in writers {
            self.reactor.react(
                Trip::Writers {
                    sandbox,
                    policy: policy.clone(),
                    host: host.clone(),
                    port,
                },
                now,
                http.base.time,
            );
        }
    }
}

#[tonic::async_trait]
impl LogsService for Detector {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let records = request
            .into_inner()
            .resource_logs
            .into_iter()
            .flat_map(|resource| resource.scope_logs)
            .flat_map(|scope| scope.log_records);
        for record in records {
            let Some(Value::StringValue(body)) = record.body.and_then(|body| body.value) else {
                continue;
            };
            // The body is the OCSF JSON record.
            if let Ok(event) = serde_json::from_str::<OcsfEvent>(&body) {
                self.ingest(&event);
            }
        }
        Ok(Response::new(ExportLogsServiceResponse::default()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let reactor = Reactor {
        reaction: cli.reaction,
        openshell: cli.openshell.clone(),
        gateway: cli.gateway.clone(),
        workspace: cli.workspace.clone(),
        dry_run: cli.dry_run,
    };
    let state = State {
        seen: HashSet::new(),
        seen_order: VecDeque::new(),
        volume: VolumeRule::new(cli.max_bytes, cli.window, cli.cooldown),
        writers: DistinctRule::new(cli.max_writers, cli.writers_window, cli.cooldown),
    };
    log(&format!(
        "listening on {}; reaction={:?} volume>{}B/{:?} ({:?}) writers>{}/{:?}",
        cli.listen,
        cli.reaction,
        cli.max_bytes,
        cli.window,
        cli.direction,
        cli.max_writers,
        cli.writers_window,
    ));
    let listen = cli.listen;
    let detector = Detector {
        cli: Arc::new(cli),
        reactor,
        state: Arc::new(Mutex::new(state)),
    };
    Server::builder()
        // The collector's OTLP exporter compresses with gzip by default.
        .add_service(LogsServiceServer::new(detector).accept_compressed(CompressionEncoding::Gzip))
        .serve(listen)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Close event as a supervisor exports it.
    const CLOSE_EVENT: &str = r#"{"class_uid":4001,"class_name":"Network Activity","category_uid":4,"category_name":"Network Activity","activity_id":2,"activity_name":"Close","type_uid":400102,"type_name":"Network Activity: Close","time":1793658742379,"severity_id":1,"severity":"Informational","status_id":1,"status":"Success","message":"CLOSE 172.22.0.2:8080 in=1572864 out=0","metadata":{"version":"1.8.0","product":{"name":"OpenShell Sandbox Supervisor","vendor_name":"OpenShell","version":"0.1.7"},"profiles":["security_control","network_proxy","container","host"],"uid":"74983dd9-7dc3-47fd-bc6a-91d33f211418"},"device":{"hostname":"host","type_id":99,"type":"Sandbox","os":{"name":"Linux","type_id":200,"type":"Linux"}},"container":{"name":"sb-22","uid":"fa86f9e5-8fa1-41ca-9a63-d02de84d8821"},"dst_endpoint":{"domain":"172.22.0.2","port":8080},"proxy_endpoint":{"ip":"127.0.0.1","port":3128},"actor":{"process":{"name":"/usr/local/bin/python3.13","pid":0}},"firewall_rule":{"name":"pkg_proxy","type":"opa"},"connection_info":{"protocol_name":"tcp","direction_id":0,"direction":"Unknown","uid":"conn-f4ab6d8c-e159-4df9-8c43-79c9127a0bc2"},"action_id":1,"action":"Allowed","disposition_id":1,"disposition":"Allowed","is_src_dst_assignment_known":true,"traffic":{"bytes_in":1572864,"bytes_out":0,"bytes":1572864},"cumulative_traffic":{"bytes_in":28195424,"bytes_out":107,"bytes":28195531},"start_time":1793658736378,"end_time":1793658741992,"duration":5614}"#;

    #[test]
    fn close_event_parses_into_typed_fields() {
        let event: OcsfEvent = serde_json::from_str(CLOSE_EVENT).unwrap();
        let OcsfEvent::NetworkActivity(network) = &event else {
            panic!("expected Network Activity, got {event:?}");
        };
        assert_eq!(network.base.activity_id, ACTIVITY_CLOSE);
        assert_eq!(sandbox_of(&event), "sb-22");
        assert_eq!(network.firewall_rule.as_ref().unwrap().name, "pkg_proxy");
        assert_eq!(network.traffic.traffic.unwrap().bytes, 1_572_864);
        assert_eq!(
            network.traffic.cumulative_traffic.unwrap().bytes,
            28_195_531
        );
        assert_eq!(network.traffic.end_time, Some(1_793_658_741_992));
    }

    #[test]
    fn sizes_and_durations_parse() {
        assert_eq!(parse_bytes("20MB"), Ok(20_000_000));
        assert_eq!(parse_duration("300s"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
    }
}
