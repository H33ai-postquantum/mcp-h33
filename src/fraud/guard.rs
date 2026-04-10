//! FraudGuard — composed entry point for the MCP fraud protection layer.
//!
//! Wires nullifier, anomaly, risk, transcript, and binary-minimization
//! into a single API surface used by the tool dispatch loop.

use crate::fraud::alerts::{AlertEvent, AlertPayload, AlertPipeline};
use crate::fraud::anomaly::{AnomalyRegistry, CallRecord};
use crate::fraud::nullifier::{NullifierCache, NullifierResult};
use crate::fraud::responses::{minimize, AuthBoundaryError, MinimizedError};
use crate::fraud::risk::{RiskEvent, RiskRegistry, SessionMode};
use crate::fraud::transcript::{Outcome, SessionTranscript};
use std::sync::Arc;
use std::time::Instant;

/// Result of evaluating a tool call against the fraud layer.
#[derive(Debug)]
pub struct Verdict {
    pub allowed: bool,
    pub mode: SessionMode,
    pub dry_run: bool,
    pub rejection: Option<MinimizedError>,
    pub handle: VerdictHandle,
}

#[derive(Debug, Clone)]
pub struct VerdictHandle {
    pub session_id: String,
    pub tool_name: String,
    pub started_at: Instant,
    pub nullifier: String,
    pub is_write: bool,
}

#[derive(Debug)]
pub struct FraudGuard {
    nullifiers: NullifierCache,
    anomaly: AnomalyRegistry,
    risk: RiskRegistry,
    session_secret: String,
    transcript: Option<Arc<SessionTranscript>>,
    alerts: Arc<AlertPipeline>,
}

#[derive(Debug)]
pub struct FraudGuardConfig {
    pub agent_token: String,
    pub local_salt: String,
    pub transcript: Option<Arc<SessionTranscript>>,
    pub alerts: Arc<AlertPipeline>,
}

impl FraudGuard {
    pub fn new(config: FraudGuardConfig) -> Self {
        let session_secret = NullifierCache::mint_session_secret(
            &config.agent_token,
            &config.local_salt,
        );
        Self {
            nullifiers: NullifierCache::new(),
            anomaly: AnomalyRegistry::new(),
            risk: RiskRegistry::new(),
            session_secret,
            transcript: config.transcript,
            alerts: config.alerts,
        }
    }

    pub fn evaluate_call(
        &self,
        session_id: &str,
        tool_name: &str,
        tool_call_id: &str,
        is_write: bool,
    ) -> Verdict {
        let started_at = Instant::now();
        let now_ms = chrono::Utc::now().timestamp_millis();

        // Immediate reject if session is already revoked
        let (_score, current_mode) = self.risk.current(session_id);
        if matches!(current_mode, SessionMode::Revoked) {
            return Verdict {
                allowed: false,
                mode: SessionMode::Revoked,
                dry_run: false,
                rejection: Some(minimize(AuthBoundaryError::Denied)),
                handle: VerdictHandle {
                    session_id: session_id.to_string(),
                    tool_name: tool_name.to_string(),
                    started_at,
                    nullifier: String::new(),
                    is_write,
                },
            };
        }

        // Nullifier check — Patent Claim 129
        let NullifierResult { ok, nullifier, .. } =
            self.nullifiers
                .check_and_record(&self.session_secret, tool_call_id, now_ms);
        if !ok {
            self.risk.update(session_id, RiskEvent::NullifierCollision);
            return Verdict {
                allowed: false,
                mode: current_mode,
                dry_run: false,
                rejection: Some(minimize(AuthBoundaryError::Duplicate)),
                handle: VerdictHandle {
                    session_id: session_id.to_string(),
                    tool_name: tool_name.to_string(),
                    started_at,
                    nullifier,
                    is_write,
                },
            };
        }

        // Write gate — Shadow allows dry-run, ReadOnly blocks
        if is_write && !current_mode.can_write() {
            return Verdict {
                allowed: false,
                mode: current_mode,
                dry_run: false,
                rejection: Some(minimize(AuthBoundaryError::Denied)),
                handle: VerdictHandle {
                    session_id: session_id.to_string(),
                    tool_name: tool_name.to_string(),
                    started_at,
                    nullifier,
                    is_write,
                },
            };
        }

        Verdict {
            allowed: true,
            mode: current_mode,
            dry_run: current_mode.writes_dry_run() && is_write,
            rejection: None,
            handle: VerdictHandle {
                session_id: session_id.to_string(),
                tool_name: tool_name.to_string(),
                started_at,
                nullifier,
                is_write,
            },
        }
    }

    pub fn record_outcome(&self, handle: &VerdictHandle, was_error: bool) {
        // Update behavioral baseline
        self.anomaly.record(
            &handle.session_id,
            &handle.tool_name,
            CallRecord {
                at: handle.started_at,
                is_write: handle.is_write,
                was_error,
            },
        );

        // Evaluate anomaly signal and feed back into risk score
        let signal = self.anomaly.evaluate(&handle.session_id, Instant::now());
        if signal.baseline_ready
            && signal.score > crate::fraud::anomaly::ANOMALY_THRESHOLD
        {
            let (score, mode) = self.risk.update(&handle.session_id, RiskEvent::AnomalyThreshold);
            // Fire an anomaly alert if we crossed into shadow/read_only/revoked
            if !matches!(mode, SessionMode::Normal) {
                self.alerts.fire(AlertPayload {
                    event: AlertEvent::AnomalyDetected,
                    session_id: handle.session_id.clone(),
                    timestamp_ms: chrono::Utc::now().timestamp_millis(),
                    human_user_id: None,
                    agent_identifier: None,
                    risk_score: Some(score),
                    mode: Some(mode.as_str().to_string()),
                    reasons: Some(signal.reasons.clone()),
                    substrate_anchor: None,
                    hats_proof: None,
                    recommended_action: Some("review_session".into()),
                    extra: None,
                });
            }
        } else if !was_error {
            self.risk.update(&handle.session_id, RiskEvent::SuccessfulCall);
        }

        // Record into the substrate transcript chain
        if let Some(t) = &self.transcript {
            let outcome = if was_error { Outcome::Error } else { Outcome::Success };
            t.record_call(&handle.tool_name, outcome, handle.is_write);
        }
    }

    /// Report a fraud-relevant event that occurred outside of evaluate_call —
    /// e.g. the dispatcher rejected an unknown tool name, or a capability
    /// check failed downstream of evaluate_call.
    pub fn report_event(&self, session_id: &str, event: RiskEvent) -> (f64, SessionMode) {
        let (score, mode) = self.risk.update(session_id, event);
        if !matches!(mode, SessionMode::Normal) {
            self.alerts.fire(AlertPayload {
                event: AlertEvent::ModeChanged,
                session_id: session_id.to_string(),
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
                human_user_id: None,
                agent_identifier: None,
                risk_score: Some(score),
                mode: Some(mode.as_str().to_string()),
                reasons: None,
                substrate_anchor: None,
                hats_proof: None,
                recommended_action: Some("investigate".into()),
                extra: None,
            });
        }
        (score, mode)
    }

    pub fn nullifier_size(&self) -> usize {
        self.nullifiers.size()
    }

    pub fn snapshot(&self, session_id: &str) -> Snapshot {
        let (score, mode) = self.risk.current(session_id);
        let stats = self
            .anomaly
            .stats(session_id)
            .unwrap_or(crate::fraud::anomaly::SessionStats {
                total_calls: 0,
                write_calls: 0,
                error_calls: 0,
                unique_tools: 0,
                baseline_ready: false,
            });
        Snapshot {
            session_id: session_id.to_string(),
            risk_score: score,
            mode,
            total_calls: stats.total_calls,
            write_calls: stats.write_calls,
            error_calls: stats.error_calls,
            unique_tools: stats.unique_tools,
            baseline_ready: stats.baseline_ready,
            nullifier_cache_size: self.nullifiers.size(),
        }
    }

    pub fn alerts(&self) -> Arc<AlertPipeline> {
        Arc::clone(&self.alerts)
    }

    pub fn evict_session(&self, session_id: &str) {
        self.anomaly.evict(session_id);
        self.risk.evict(session_id);
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub session_id: String,
    pub risk_score: f64,
    pub mode: SessionMode,
    pub total_calls: u32,
    pub write_calls: u32,
    pub error_calls: u32,
    pub unique_tools: usize,
    pub baseline_ready: bool,
    pub nullifier_cache_size: usize,
}
