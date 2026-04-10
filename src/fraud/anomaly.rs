//! Behavioral Anomaly Detection
//!
//! Patent Claim 128 (FraudShield absorption). Each MCP session establishes
//! a behavioral baseline over its first ~20 calls, then compares each new
//! call against the baseline. Anomalies above threshold push the session
//! into shadow mode.
//!
//! V1: plaintext numeric features. V2 (future): swap to CKKS-encrypted
//! feature vectors with comparisons performed homomorphically via H33
//! FHE endpoints in scif-backend.

use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const WARMUP_CALLS: u32 = 20;
const SLIDING_WINDOW_MS: u64 = 60_000;
const MAX_HISTORY: usize = 500;
pub const ANOMALY_THRESHOLD: f64 = 0.35;

#[derive(Debug, Clone, Copy)]
pub struct CallRecord {
    pub at: Instant,
    pub is_write: bool,
    pub was_error: bool,
}

#[derive(Debug, Clone)]
pub struct AnomalySignal {
    pub score: f64,
    pub reasons: Vec<String>,
    pub baseline_ready: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct Snapshot {
    calls_per_minute: f64,
    write_ratio: f64,
    error_rate: f64,
    tool_diversity: usize,
    burstiness: f64,
}

#[derive(Debug)]
pub struct SessionBaseline {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    history: Vec<(String, CallRecord)>,
    tool_counts: HashMap<String, u32>,
    total_calls: u32,
    write_calls: u32,
    error_calls: u32,
    baseline: Option<Snapshot>,
    session_start: Option<Instant>,
}

impl SessionBaseline {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn record(&self, tool_name: &str, record: CallRecord) {
        let mut g = self.inner.lock();
        if g.session_start.is_none() {
            g.session_start = Some(record.at);
        }
        g.total_calls += 1;
        if record.is_write {
            g.write_calls += 1;
        }
        if record.was_error {
            g.error_calls += 1;
        }
        *g.tool_counts.entry(tool_name.to_string()).or_insert(0) += 1;
        g.history.push((tool_name.to_string(), record));
        if g.history.len() > MAX_HISTORY {
            let removed = g.history.remove(0);
            if let Some(c) = g.tool_counts.get_mut(&removed.0) {
                if *c <= 1 {
                    g.tool_counts.remove(&removed.0);
                } else {
                    *c -= 1;
                }
            }
        }

        if g.total_calls == WARMUP_CALLS {
            let snap = Self::snapshot_inner(&g, record.at);
            g.baseline = Some(snap);
        }
    }

    pub fn evaluate(&self, now: Instant) -> AnomalySignal {
        let g = self.inner.lock();
        let Some(baseline) = g.baseline else {
            return AnomalySignal {
                score: 0.0,
                reasons: Vec::new(),
                baseline_ready: false,
            };
        };
        let current = Self::snapshot_inner(&g, now);
        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();

        let rate_ratio = if baseline.calls_per_minute > 0.0 {
            current.calls_per_minute / baseline.calls_per_minute
        } else {
            1.0
        };
        if rate_ratio > 5.0 {
            score += 0.30;
            reasons.push(format!(
                "call_rate_spike ({:.1}/min vs baseline {:.1}/min)",
                current.calls_per_minute, baseline.calls_per_minute
            ));
        } else if rate_ratio > 3.0 {
            score += 0.15;
            reasons.push("call_rate_elevated".to_string());
        }

        let write_delta = (current.write_ratio - baseline.write_ratio).abs();
        if write_delta > 0.4 {
            score += 0.20;
            reasons.push(format!(
                "write_ratio_shift ({:.2} vs baseline {:.2})",
                current.write_ratio, baseline.write_ratio
            ));
        }

        if current.error_rate > 0.3 && baseline.error_rate < 0.1 {
            score += 0.25;
            reasons.push("error_rate_spike".to_string());
        }

        if current.tool_diversity > baseline.tool_diversity * 2 {
            score += 0.20;
            reasons.push("tool_diversity_explosion".to_string());
        }

        if baseline.burstiness > 0.0 && current.burstiness > baseline.burstiness * 3.0 {
            score += 0.15;
            reasons.push("call_burstiness_spike".to_string());
        }

        AnomalySignal {
            score: score.min(1.0),
            reasons,
            baseline_ready: true,
        }
    }

    fn snapshot_inner(inner: &Inner, now: Instant) -> Snapshot {
        let cutoff = now.checked_sub(Duration::from_millis(SLIDING_WINDOW_MS));
        let window: Vec<&(String, CallRecord)> = inner
            .history
            .iter()
            .filter(|(_, r)| match cutoff {
                Some(c) => r.at >= c,
                None => true,
            })
            .collect();
        let n = window.len();
        let writes = window.iter().filter(|(_, r)| r.is_write).count();
        let errors = window.iter().filter(|(_, r)| r.was_error).count();

        // Burstiness: stddev / mean of inter-call intervals
        let mut burstiness = 0.0;
        if window.len() >= 3 {
            let intervals: Vec<f64> = window
                .windows(2)
                .map(|w| w[1].1.at.duration_since(w[0].1.at).as_millis() as f64)
                .collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean > 0.0 {
                let variance = intervals
                    .iter()
                    .map(|i| (i - mean).powi(2))
                    .sum::<f64>()
                    / intervals.len() as f64;
                burstiness = variance.sqrt() / mean;
            }
        }

        let tool_diversity: HashSet<String> =
            window.iter().map(|(t, _)| t.clone()).collect();

        Snapshot {
            calls_per_minute: n as f64 * (60_000.0 / SLIDING_WINDOW_MS as f64),
            write_ratio: if n > 0 { writes as f64 / n as f64 } else { 0.0 },
            error_rate: if n > 0 { errors as f64 / n as f64 } else { 0.0 },
            tool_diversity: tool_diversity.len(),
            burstiness,
        }
    }

    pub fn stats(&self) -> SessionStats {
        let g = self.inner.lock();
        SessionStats {
            total_calls: g.total_calls,
            write_calls: g.write_calls,
            error_calls: g.error_calls,
            unique_tools: g.tool_counts.len(),
            baseline_ready: g.baseline.is_some(),
        }
    }
}

impl Default for SessionBaseline {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionStats {
    pub total_calls: u32,
    pub write_calls: u32,
    pub error_calls: u32,
    pub unique_tools: usize,
    pub baseline_ready: bool,
}

#[derive(Debug, Default)]
pub struct AnomalyRegistry {
    sessions: DashMap<String, SessionBaseline>,
}

impl AnomalyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, session_id: &str, tool_name: &str, record: CallRecord) {
        let entry = self.sessions.entry(session_id.to_string()).or_default();
        entry.record(tool_name, record);
    }

    pub fn evaluate(&self, session_id: &str, now: Instant) -> AnomalySignal {
        if let Some(s) = self.sessions.get(session_id) {
            s.evaluate(now)
        } else {
            AnomalySignal {
                score: 0.0,
                reasons: Vec::new(),
                baseline_ready: false,
            }
        }
    }

    pub fn stats(&self, session_id: &str) -> Option<SessionStats> {
        self.sessions.get(session_id).map(|s| s.stats())
    }

    pub fn evict(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}
