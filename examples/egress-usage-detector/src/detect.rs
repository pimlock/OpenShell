// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Detection rules with no I/O and no event format.
//!
//! Callers choose the keys and pass the clock, so the same rules can run
//! behind OCSF events (this detector) or middleware hooks (spike 02b).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Byte samples summed over a sliding window.
#[derive(Debug, Default)]
pub struct SlidingWindow {
    samples: VecDeque<(Instant, u64)>,
    total: u64,
}

impl SlidingWindow {
    /// Add `bytes` at `now`, drop samples older than `window`, and return the
    /// window total.
    pub fn add(&mut self, now: Instant, bytes: u64, window: Duration) -> u64 {
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

/// Trips a key once its window total exceeds `max_bytes`, then ignores the
/// key for `cooldown`.
#[derive(Debug)]
pub struct VolumeRule<K> {
    max_bytes: u64,
    window: Duration,
    cooldown: Duration,
    windows: HashMap<K, SlidingWindow>,
    tripped_until: HashMap<K, Instant>,
}

impl<K: Eq + Hash + Clone> VolumeRule<K> {
    pub fn new(max_bytes: u64, window: Duration, cooldown: Duration) -> Self {
        Self {
            max_bytes,
            window,
            cooldown,
            windows: HashMap::new(),
            tripped_until: HashMap::new(),
        }
    }

    /// Add `bytes` to the key's window. Returns the window total when the key
    /// trips.
    pub fn record(&mut self, key: &K, bytes: u64, now: Instant) -> Option<u64> {
        let total = self
            .windows
            .entry(key.clone())
            .or_default()
            .add(now, bytes, self.window);
        if total <= self.max_bytes
            || self
                .tripped_until
                .get(key)
                .is_some_and(|until| *until > now)
        {
            return None;
        }
        self.tripped_until.insert(key.clone(), now + self.cooldown);
        Some(total)
    }
}

/// Trips a group once more than `max_members` distinct members were seen in
/// it within `window`, then ignores the group for `cooldown`.
#[derive(Debug)]
pub struct DistinctRule<G, M> {
    max_members: usize,
    window: Duration,
    cooldown: Duration,
    groups: HashMap<G, HashMap<M, Instant>>,
    tripped_until: HashMap<G, Instant>,
}

impl<G: Eq + Hash + Clone, M: Eq + Hash + Clone + Ord> DistinctRule<G, M> {
    pub fn new(max_members: usize, window: Duration, cooldown: Duration) -> Self {
        Self {
            max_members,
            window,
            cooldown,
            groups: HashMap::new(),
            tripped_until: HashMap::new(),
        }
    }

    /// Record `member` in `group`. Returns the sorted members when the group
    /// trips.
    pub fn record(&mut self, group: &G, member: &M, now: Instant) -> Option<Vec<M>> {
        let members = self.groups.entry(group.clone()).or_default();
        members.insert(member.clone(), now);
        members.retain(|_, seen| now.duration_since(*seen) <= self.window);
        if members.len() <= self.max_members
            || self
                .tripped_until
                .get(group)
                .is_some_and(|until| *until > now)
        {
            return None;
        }
        let mut tripped: Vec<M> = members.keys().cloned().collect();
        tripped.sort();
        self.tripped_until
            .insert(group.clone(), now + self.cooldown);
        Some(tripped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn window_expires_old_samples() {
        let mut window = SlidingWindow::default();
        let start = Instant::now();
        assert_eq!(window.add(start, 10, MINUTE), 10);
        assert_eq!(window.add(start + Duration::from_secs(30), 5, MINUTE), 15);
        assert_eq!(window.add(start + Duration::from_secs(61), 1, MINUTE), 6);
    }

    #[test]
    fn volume_trips_once_per_cooldown() {
        let mut rule = VolumeRule::new(100, MINUTE, Duration::from_secs(300));
        let start = Instant::now();
        let key = ("sb".to_string(), "pkg".to_string());
        assert_eq!(rule.record(&key, 60, start), None);
        assert_eq!(rule.record(&key, 60, start), Some(120));
        assert_eq!(rule.record(&key, 60, start), None);
        assert_eq!(
            rule.record(&key, 200, start + Duration::from_secs(301)),
            Some(200)
        );
    }

    #[test]
    fn distinct_counts_members_within_the_window() {
        let mut rule = DistinctRule::new(2, MINUTE, Duration::from_secs(300));
        let start = Instant::now();
        let host = "files".to_string();
        assert_eq!(rule.record(&host, &"a", start), None);
        assert_eq!(rule.record(&host, &"b", start), None);
        assert_eq!(rule.record(&host, &"a", start), None);
        // "a" and "b" expire before "c" arrives.
        assert_eq!(
            rule.record(&host, &"c", start + Duration::from_secs(61)),
            None
        );
        assert_eq!(
            rule.record(&host, &"d", start + Duration::from_secs(62)),
            None
        );
        assert_eq!(
            rule.record(&host, &"e", start + Duration::from_secs(63)),
            Some(vec!["c", "d", "e"])
        );
    }
}
