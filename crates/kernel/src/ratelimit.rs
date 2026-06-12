//! In-process brute-force protection for login.
//!
//! A fixed-window failure counter per key (`tenant|email`). After
//! [`MAX_FAILURES`] failed attempts within [`WINDOW_SECS`] the key is locked
//! until the window expires, and further attempts return `RateLimited` without
//! touching the database or doing password work. Per-node state is sufficient
//! here: an attacker hammering one node is throttled on that node, and the
//! Argon2 cost already bounds offline guessing.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const MAX_FAILURES: u32 = 10;
pub(crate) const WINDOW_SECS: u64 = 900; // 15 minutes

#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    window_start: Instant,
    failures: u32,
}

/// Shared login failure tracker. Cheap to clone via `Arc` on the kernel.
#[derive(Debug, Default)]
pub(crate) struct LoginLimiter {
    state: Mutex<HashMap<String, FailureWindow>>,
}

impl LoginLimiter {
    /// Is this key currently locked out?
    pub(crate) fn is_locked(&self, key: &str) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match state.get(key).copied() {
            Some(w) => {
                if w.window_start.elapsed() >= Duration::from_secs(WINDOW_SECS) {
                    state.remove(key);
                    false
                } else {
                    w.failures >= MAX_FAILURES
                }
            }
            None => false,
        }
    }

    /// Record a failed attempt; returns the failure count in the current window.
    pub(crate) fn record_failure(&self, key: &str) -> u32 {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let entry = state.entry(key.to_string()).or_insert(FailureWindow {
            window_start: now,
            failures: 0,
        });
        if entry.window_start.elapsed() >= Duration::from_secs(WINDOW_SECS) {
            entry.window_start = now;
            entry.failures = 0;
        }
        entry.failures += 1;
        entry.failures
    }

    /// Clear failures after a successful login.
    pub(crate) fn reset(&self, key: &str) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.remove(key);
    }

    /// Drop stale windows so the map cannot grow unboundedly under a
    /// many-usernames attack. Called from periodic housekeeping.
    pub(crate) fn prune(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.retain(|_, w| w.window_start.elapsed() < Duration::from_secs(WINDOW_SECS));
    }
}
