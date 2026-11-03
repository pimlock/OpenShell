// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Limits from the policy's middleware config, with flag defaults.
//!
//! ```yaml
//! config:
//!   max_bytes: 20MB
//!   window: 60s
//!   interval: 5s
//!   block_for: 300s
//!   direction: both
//!   policies:
//!     other_svc:
//!       max_bytes: 5MB
//! ```
//!
//! Every field is optional. Top-level fields override the service flags, and
//! `policies.<key>` overrides them for one network policy key.

use std::collections::HashMap;
use std::time::Duration;

use prost_types::Struct;
use prost_types::value::Kind;

use crate::usage::{Direction, Limits};

/// OpenShell clamps stats intervals to this range.
const MIN_INTERVAL: Duration = Duration::from_secs(1);
const MAX_INTERVAL: Duration = Duration::from_mins(1);

#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    limits: Limits,
    policies: HashMap<String, Limits>,
}

impl Config {
    pub fn parse(config: Option<&Struct>, defaults: Limits) -> Result<Self, String> {
        let Some(config) = config else {
            return Ok(Self {
                limits: defaults,
                policies: HashMap::new(),
            });
        };
        let limits = parse_limits(config, defaults, "config", true)?;
        let mut policies = HashMap::new();
        if let Some(value) = config.fields.get("policies") {
            let Some(Kind::StructValue(entries)) = &value.kind else {
                return Err("config.policies must be a map of policy key to limits".into());
            };
            for (key, value) in &entries.fields {
                let Some(Kind::StructValue(fields)) = &value.kind else {
                    return Err(format!("config.policies.{key} must be a map"));
                };
                let path = format!("config.policies.{key}");
                policies.insert(key.clone(), parse_limits(fields, limits, &path, false)?);
            }
        }
        Ok(Self { limits, policies })
    }

    pub fn limits_for(&self, policy_key: &str) -> Limits {
        self.policies
            .get(policy_key)
            .copied()
            .unwrap_or(self.limits)
    }
}

fn parse_limits(
    fields: &Struct,
    base: Limits,
    path: &str,
    top_level: bool,
) -> Result<Limits, String> {
    if let Some(field) = fields.fields.keys().find(|field| match field.as_str() {
        "max_bytes" | "window" | "interval" | "block_for" | "direction" => false,
        "policies" => !top_level,
        _ => true,
    }) {
        return Err(format!("unsupported field '{path}.{field}'"));
    }
    let mut limits = base;
    for (name, value) in &fields.fields {
        let field = format!("{path}.{name}");
        match name.as_str() {
            "max_bytes" => {
                limits.max_bytes = value_with(value, &field, parse_bytes, |bytes| bytes)?
            }
            "window" => limits.window = duration(value, &field)?,
            "interval" => limits.interval = duration(value, &field)?,
            "block_for" => limits.block_for = duration(value, &field)?,
            "direction" => {
                let Some(Kind::StringValue(direction)) = &value.kind else {
                    return Err(format!("{field} must be 'both', 'in', or 'out'"));
                };
                limits.direction = match direction.as_str() {
                    "both" => Direction::Both,
                    "in" => Direction::In,
                    "out" => Direction::Out,
                    _ => return Err(format!("{field} must be 'both', 'in', or 'out'")),
                };
            }
            _ => {}
        }
    }
    if limits.max_bytes == 0 {
        return Err(format!("{path}.max_bytes must be greater than zero"));
    }
    if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&limits.interval) {
        return Err(format!("{path}.interval must be between 1s and 60s"));
    }
    if limits.window < limits.interval {
        return Err(format!("{path}.window must be at least the interval"));
    }
    Ok(limits)
}

fn duration(value: &prost_types::Value, field: &str) -> Result<Duration, String> {
    value_with(value, field, parse_duration, Duration::from_secs)
}

/// Accepts a string with units, or a number in base units (bytes, seconds).
fn value_with<T>(
    value: &prost_types::Value,
    field: &str,
    parse: fn(&str) -> Result<T, String>,
    from_number: impl Fn(u64) -> T,
) -> Result<T, String> {
    match &value.kind {
        Some(Kind::StringValue(text)) => parse(text).map_err(|error| format!("{field}: {error}")),
        Some(Kind::NumberValue(number)) if *number >= 0.0 && number.fract() == 0.0 =>
        {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Ok(from_number(*number as u64))
        }
        _ => Err(format!(
            "{field} must be a string such as '20MB' or '60s', or a whole number"
        )),
    }
}

pub fn parse_bytes(value: &str) -> Result<u64, String> {
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

pub fn parse_duration(value: &str) -> Result<Duration, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::Value;

    fn defaults() -> Limits {
        Limits {
            max_bytes: 20_000_000,
            window: Duration::from_secs(60),
            interval: Duration::from_secs(5),
            block_for: Duration::from_secs(300),
            direction: Direction::Both,
        }
    }

    fn text(value: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(value.into())),
        }
    }

    fn map(fields: Vec<(&str, Value)>) -> Struct {
        Struct {
            fields: fields
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
        }
    }

    #[test]
    fn parses_sizes_and_durations() {
        assert_eq!(parse_bytes("20MB").unwrap(), 20_000_000);
        assert_eq!(parse_bytes("512").unwrap(), 512);
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn missing_config_uses_flag_defaults() {
        let config = Config::parse(None, defaults()).unwrap();
        assert_eq!(config.limits_for("pkg_proxy"), defaults());
    }

    #[test]
    fn policy_overrides_inherit_top_level_fields() {
        let config = map(vec![
            ("max_bytes", text("10MB")),
            (
                "interval",
                Value {
                    kind: Some(Kind::NumberValue(1.0)),
                },
            ),
            (
                "policies",
                Value {
                    kind: Some(Kind::StructValue(map(vec![(
                        "other_svc",
                        Value {
                            kind: Some(Kind::StructValue(map(vec![
                                ("max_bytes", text("5MB")),
                                ("direction", text("in")),
                            ]))),
                        },
                    )]))),
                },
            ),
        ]);
        let config = Config::parse(Some(&config), defaults()).unwrap();
        let pkg = config.limits_for("pkg_proxy");
        assert_eq!(pkg.max_bytes, 10_000_000);
        assert_eq!(pkg.interval, Duration::from_secs(1));
        let other = config.limits_for("other_svc");
        assert_eq!(other.max_bytes, 5_000_000);
        assert_eq!(other.interval, Duration::from_secs(1));
        assert_eq!(other.direction, Direction::In);
    }

    #[test]
    fn rejects_bad_config() {
        for (config, error) in [
            (map(vec![("max_bytes", text("lots"))]), "invalid byte size"),
            (map(vec![("max_bytes", text("0"))]), "greater than zero"),
            (map(vec![("interval", text("100ms"))]), "between 1s and 60s"),
            (map(vec![("window", text("2s"))]), "at least the interval"),
            (
                map(vec![("direction", text("up"))]),
                "'both', 'in', or 'out'",
            ),
            (
                map(vec![("budget", text("1MB"))]),
                "unsupported field 'config.budget'",
            ),
            (
                map(vec![(
                    "policies",
                    Value {
                        kind: Some(Kind::StructValue(map(vec![(
                            "other_svc",
                            Value {
                                kind: Some(Kind::StructValue(map(vec![("policies", text("x"))]))),
                            },
                        )]))),
                    },
                )]),
                "unsupported field 'config.policies.other_svc.policies'",
            ),
        ] {
            let result = Config::parse(Some(&config), defaults());
            assert!(
                result
                    .as_ref()
                    .is_err_and(|message| message.contains(error)),
                "{result:?} should contain {error}"
            );
        }
    }
}
