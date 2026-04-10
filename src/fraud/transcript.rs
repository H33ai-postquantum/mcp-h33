//! Substrate-Anchored Session Transcript
//!
//! Patent Extension 22 — every 60 seconds the MCP server commits an
//! AUDIT_ENTRY (0x59) substrate anchor summarizing session activity. Each
//! anchor references the prior anchor's commitment, producing a tamper-
//! evident chain. On session end, an AUDIT_SEAL (0x5A) anchor commits to
//! the full chain.

use parking_lot::Mutex;
use serde::Serialize;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::client::H33ApiClient;
use crate::Result;

#[derive(Debug, Clone, Serialize)]
pub struct TranscriptEntry {
    pub anchor_id: String,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    pub call_count: u32,
    pub write_count: u32,
    pub error_count: u32,
    pub tool_histogram: HashMap<String, u32>,
    pub outcome_histogram: OutcomeHistogram,
    pub anomaly_score_hash: String,
    pub prior_anchor: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OutcomeHistogram {
    pub success: u32,
    pub denied: u32,
    pub error: u32,
}

#[derive(Debug)]
struct PeriodState {
    period_start_ms: i64,
    calls: u32,
    writes: u32,
    errors: u32,
    tool_histogram: HashMap<String, u32>,
    outcomes: OutcomeHistogram,
}

impl PeriodState {
    fn new() -> Self {
        Self {
            period_start_ms: chrono::Utc::now().timestamp_millis(),
            calls: 0,
            writes: 0,
            errors: 0,
            tool_histogram: HashMap::new(),
            outcomes: OutcomeHistogram::default(),
        }
    }

    fn record(&mut self, tool: &str, outcome: Outcome, is_write: bool) {
        self.calls += 1;
        if is_write {
            self.writes += 1;
        }
        match outcome {
            Outcome::Success => self.outcomes.success += 1,
            Outcome::Denied => self.outcomes.denied += 1,
            Outcome::Error => {
                self.outcomes.error += 1;
                self.errors += 1;
            }
        }
        *self.tool_histogram.entry(tool.to_string()).or_insert(0) += 1;
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Success,
    Denied,
    Error,
}

#[derive(Debug)]
pub struct SessionTranscript {
    session_id: String,
    api: Arc<H33ApiClient>,
    period_ms: u64,
    state: Mutex<PeriodState>,
    chain: Mutex<Vec<TranscriptEntry>>,
}

impl SessionTranscript {
    pub fn new(session_id: String, api: Arc<H33ApiClient>, period: Duration) -> Arc<Self> {
        Arc::new(Self {
            session_id,
            api,
            period_ms: period.as_millis() as u64,
            state: Mutex::new(PeriodState::new()),
            chain: Mutex::new(Vec::new()),
        })
    }

    pub fn record_call(&self, tool: &str, outcome: Outcome, is_write: bool) {
        let mut s = self.state.lock();
        s.record(tool, outcome, is_write);
    }

    /// Spawn the periodic flush task. Returns a JoinHandle the caller can
    /// abort on shutdown.
    pub fn spawn_periodic_flush(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        let period = Duration::from_millis(me.period_ms);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // immediate fire is intentionally consumed
            loop {
                tick.tick().await;
                if let Err(e) = me.flush().await {
                    tracing::warn!("transcript flush: {}", e);
                }
            }
        })
    }

    /// Flush the current period to a substrate AUDIT_ENTRY anchor.
    /// No-op if the current period has zero activity.
    pub async fn flush(&self) -> Result<Option<TranscriptEntry>> {
        // Snapshot and reset the period under the lock
        let snapshot = {
            let mut s = self.state.lock();
            if s.calls == 0 {
                return Ok(None);
            }
            let snapshot = PeriodState {
                period_start_ms: s.period_start_ms,
                calls: s.calls,
                writes: s.writes,
                errors: s.errors,
                tool_histogram: s.tool_histogram.clone(),
                outcomes: s.outcomes.clone(),
            };
            s.reset();
            snapshot
        };

        let now_ms = chrono::Utc::now().timestamp_millis();

        let prior_anchor = {
            let chain = self.chain.lock();
            chain.last().map(|e| e.anchor_id.clone())
        };

        let prior_commitment = prior_anchor.as_deref().map(extract_commitment);

        let payload = serde_json::json!({
            "session_id": self.session_id,
            "period_start": snapshot.period_start_ms,
            "period_end": now_ms,
            "call_count": snapshot.calls,
            "write_count": snapshot.writes,
            "error_count": snapshot.errors,
            "tool_histogram": snapshot.tool_histogram,
            "outcome_histogram": snapshot.outcomes,
            "prior_anchor": prior_commitment,
        });

        let anchor_id = self
            .api
            .substrate_enroll_json("0x59", &payload, Some("mcp_session_transcript"))
            .await?;

        let anomaly_hash = hash_payload(&payload);
        let entry = TranscriptEntry {
            anchor_id: anchor_id.clone(),
            period_start_ms: snapshot.period_start_ms,
            period_end_ms: now_ms,
            call_count: snapshot.calls,
            write_count: snapshot.writes,
            error_count: snapshot.errors,
            tool_histogram: snapshot.tool_histogram,
            outcome_histogram: snapshot.outcomes,
            anomaly_score_hash: anomaly_hash,
            prior_anchor: prior_commitment,
        };

        self.chain.lock().push(entry.clone());
        Ok(Some(entry))
    }

    /// Commit the final AUDIT_SEAL (0x5A) anchor for the session.
    /// Computes a SHA3-256 chain hash over all entry anchors in order.
    pub async fn seal(&self) -> Result<Option<SealReceipt>> {
        // Final flush
        self.flush().await?;

        let chain = self.chain.lock().clone();
        if chain.is_empty() {
            return Ok(None);
        }

        let mut hasher = Sha3_256::new();
        hasher.update(b"h33-mcp/v1/session-seal");
        hasher.update([0u8]);
        hasher.update(self.session_id.as_bytes());
        for entry in &chain {
            hasher.update([0u8]);
            hasher.update(entry.anchor_id.as_bytes());
        }
        let chain_hash = hex::encode(hasher.finalize());

        let payload = serde_json::json!({
            "session_id": self.session_id,
            "chain_length": chain.len(),
            "session_start": chain[0].period_start_ms,
            "session_end": chain[chain.len() - 1].period_end_ms,
            "total_calls": chain.iter().map(|e| e.call_count).sum::<u32>(),
            "total_writes": chain.iter().map(|e| e.write_count).sum::<u32>(),
            "total_errors": chain.iter().map(|e| e.error_count).sum::<u32>(),
            "chain_hash": chain_hash,
        });

        let seal_anchor = self
            .api
            .substrate_enroll_json("0x5A", &payload, Some("mcp_session_seal"))
            .await?;

        Ok(Some(SealReceipt {
            anchor_id: seal_anchor,
            chain_length: chain.len(),
        }))
    }

    pub fn chain_length(&self) -> usize {
        self.chain.lock().len()
    }
}

#[derive(Debug, Clone)]
pub struct SealReceipt {
    pub anchor_id: String,
    pub chain_length: usize,
}

fn extract_commitment(anchor_id: &str) -> String {
    // Anchor IDs encode 74 bytes as 148 hex chars; first 64 chars are the commitment
    anchor_id.chars().take(64).collect()
}

fn hash_payload(payload: &serde_json::Value) -> String {
    let mut hasher = Sha3_256::new();
    let s = payload.to_string();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}
