// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reactions through the public `openshell` CLI.

use std::process::Output;
use std::time::Instant;

use tokio::process::Command;

use crate::{log, now_ms};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Reaction {
    /// `openshell sandbox stop <sandbox>`.
    Stop,
    /// Remove the policy key (volume) or append a PUT deny rule (writers).
    Deny,
}

/// What tripped, and against which sandbox and policy key.
#[derive(Debug, Clone)]
pub enum Trip {
    Volume {
        sandbox: String,
        policy: String,
    },
    Writers {
        sandbox: String,
        policy: String,
        host: String,
        port: Option<u16>,
    },
}

#[derive(Debug, Clone)]
pub struct Reactor {
    pub reaction: Reaction,
    pub openshell: String,
    pub gateway: Option<String>,
    pub workspace: Option<String>,
    pub dry_run: bool,
}

impl Reactor {
    /// React to `trip` in the background. `event_ms` is the supervisor's event
    /// time, used to report end-to-end latency.
    pub fn react(&self, trip: Trip, tripped_at: Instant, event_ms: i64) {
        let reactor = self.clone();
        tokio::spawn(async move { reactor.run(trip, tripped_at, event_ms).await });
    }

    async fn run(&self, trip: Trip, tripped_at: Instant, event_ms: i64) {
        let (kind, sandbox, args) = match (&trip, self.reaction) {
            (Trip::Volume { sandbox, .. } | Trip::Writers { sandbox, .. }, Reaction::Stop) => (
                "stop",
                sandbox,
                vec!["sandbox".into(), "stop".into(), sandbox.clone()],
            ),
            (Trip::Volume { sandbox, policy }, Reaction::Deny) => (
                "volume",
                sandbox,
                vec![
                    "policy".into(),
                    "update".into(),
                    sandbox.clone(),
                    "--remove-rule".into(),
                    policy.clone(),
                ],
            ),
            (
                Trip::Writers {
                    sandbox,
                    policy,
                    host,
                    port,
                },
                Reaction::Deny,
            ) => {
                let target = port.map_or_else(|| host.clone(), |port| format!("{host}:{port}"));
                let mut args = vec![
                    "policy".into(),
                    "update".into(),
                    sandbox.clone(),
                    "--add-deny".into(),
                    format!("{target}:PUT:/**"),
                    "--rule-name".into(),
                    policy.clone(),
                ];
                args.extend(self.binary_scope(sandbox, policy).await);
                ("writers", sandbox, args)
            }
        };
        if self.dry_run {
            log(&format!("DRY RUN openshell {}", args.join(" ")));
            return;
        }
        let output = self.cli(&args).await;
        let status = match &output {
            Ok(output) if output.status.success() => "ok".to_string(),
            Ok(output) => format!("{}", output.status),
            Err(error) => error.to_string(),
        };
        log(&format!(
            "REACT {kind} {:?} sandbox={sandbox} [{status}] detect->react {} ms, \
             supervisor event->react {} ms: {}",
            self.reaction,
            tripped_at.elapsed().as_millis(),
            now_ms() - event_ms,
            args.join(" "),
        ));
        if let Ok(output) = output
            && !output.status.success()
        {
            log(&format!(
                "  stderr: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }

    /// CLI flags naming the rule's complete binary list.
    ///
    /// An L7 append must restate the target rule's binaries exactly, so read
    /// them from the sandbox's base policy. A rule without binaries allows any
    /// binary.
    async fn binary_scope(&self, sandbox: &str, policy: &str) -> Vec<String> {
        let args: Vec<String> = ["policy", "get", sandbox, "--base", "-o", "json"]
            .map(String::from)
            .into();
        let paths = match self.cli(&args).await {
            Ok(output) => serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .ok()
                .and_then(|policy_json| {
                    let rule = &policy_json["policy"]["network_policies"][policy];
                    (!rule.is_null()).then(|| {
                        rule["binaries"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|binary| binary["path"].as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                }),
            Err(_) => None,
        };
        match paths {
            Some(paths) if !paths.is_empty() => paths
                .into_iter()
                .flat_map(|path| ["--binary".to_string(), path])
                .collect(),
            Some(_) => vec!["--any-binary".into()],
            None => {
                log(&format!(
                    "  could not read binaries of {sandbox}/{policy}; using --any-binary"
                ));
                vec!["--any-binary".into()]
            }
        }
    }

    async fn cli(&self, args: &[String]) -> std::io::Result<Output> {
        let mut command = Command::new(&self.openshell);
        if let Some(gateway) = &self.gateway {
            command.args(["--gateway", gateway]);
        }
        if let Some(workspace) = &self.workspace {
            command.env("OPENSHELL_WORKSPACE", workspace);
        }
        command.args(args).output().await
    }
}
