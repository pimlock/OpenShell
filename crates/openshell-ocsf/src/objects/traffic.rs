// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `network_traffic` object.

use serde::{Deserialize, Serialize};

/// OCSF Network Traffic object.
///
/// The supervisor is a userspace proxy, so it reports socket bytes only and
/// never packet counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NetworkTraffic {
    /// Bytes received from the remote endpoint.
    pub bytes_in: u64,
    /// Bytes sent to the remote endpoint.
    pub bytes_out: u64,
    /// `bytes_in + bytes_out`.
    pub bytes: u64,
}

impl NetworkTraffic {
    #[must_use]
    pub fn new(bytes_in: u64, bytes_out: u64) -> Self {
        Self {
            bytes_in,
            bytes_out,
            bytes: bytes_in.saturating_add(bytes_out),
        }
    }
}

/// Traffic amounts and the time window they cover, carried by Network
/// Activity `Traffic` (interval deltas) and `Close` (totals) events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub struct TrafficReport {
    /// Amounts for this event's window (OCSF reserves `traffic` for deltas).
    #[serde(default)]
    pub traffic: Option<NetworkTraffic>,
    /// Totals over the life of the connection.
    #[serde(default)]
    pub cumulative_traffic: Option<NetworkTraffic>,
    /// Window start, milliseconds since epoch.
    #[serde(default)]
    pub start_time: Option<i64>,
    /// Window end, milliseconds since epoch.
    #[serde(default)]
    pub end_time: Option<i64>,
    /// Connection duration in milliseconds (close events).
    #[serde(default)]
    pub duration: Option<i64>,
}
