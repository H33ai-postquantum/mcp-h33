//! Dynamic Session Risk Scoring
//!
//! Each MCP session maintains a risk score in [0.0, 1.0] that rises on
//! suspicious events and decays on legitimate calls. The score determines
//! the session's mode:
//!
//!   - risk < 0.3   → Normal
//!   - 0.3 .. 0.6   → Shadow (writes become dry-run)
//!   - 0.6 .. 0.85  → ReadOnly (no writes allowed)
//!   - ≥ 0.85       → Revoked (immediate termination + human paged)

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    Normal,
    Shadow,
    ReadOnly,
    Revoked,
}

impl SessionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionMode::Normal => "normal",
            SessionMode::Shadow => "shadow",
            SessionMode::ReadOnly => "read_only",
            SessionMode::Revoked => "revoked",
        }
    }

    pub fn writes_dry_run(&self) -> bool {
        matches!(self, SessionMode::Shadow)
    }

    pub fn can_write(&self) -> bool {
        matches!(self, SessionMode::Normal | SessionMode::Shadow)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RiskEvent {
    NullifierCollision,
    CapabilityDenial,
    AnomalyThreshold,
    TenantIsolationViolation,
    RateLimitHit,
    UnknownTool,
    SuccessfulCall,
}

impl RiskEvent {
    fn weight(&self) -> f64 {
        match self {
            RiskEvent::NullifierCollision => 0.15,
            RiskEvent::CapabilityDenial => 0.25,
            RiskEvent::AnomalyThreshold => 0.10,
            RiskEvent::TenantIsolationViolation => 0.30,
            RiskEvent::RateLimitHit => 0.05,
            RiskEvent::UnknownTool => 0.08,
            RiskEvent::SuccessfulCall => -0.03,
        }
    }
}

const DECAY_FACTOR: f64 = 0.95;

#[derive(Debug)]
pub struct SessionRisk {
    /// Score scaled to fixed-point millis (0..1000) for atomic updates
    score_milli: AtomicU64,
}

impl SessionRisk {
    pub fn new() -> Self {
        Self {
            score_milli: AtomicU64::new(0),
        }
    }

    pub fn current_score(&self) -> f64 {
        self.score_milli.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn current_mode(&self) -> SessionMode {
        Self::score_to_mode(self.current_score())
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.current_mode(), SessionMode::Revoked)
    }

    pub fn can_write(&self) -> bool {
        self.current_mode().can_write()
    }

    pub fn writes_dry_run(&self) -> bool {
        self.current_mode().writes_dry_run()
    }

    pub fn update(&self, event: RiskEvent) -> (f64, SessionMode) {
        let mut current = self.score_milli.load(Ordering::Relaxed) as f64 / 1000.0;

        if matches!(event, RiskEvent::SuccessfulCall) {
            current = (current * DECAY_FACTOR).max(0.0);
        } else {
            current = (current + event.weight()).clamp(0.0, 1.0);
        }

        let new_milli = (current * 1000.0).round() as u64;
        self.score_milli.store(new_milli, Ordering::Relaxed);
        (current, Self::score_to_mode(current))
    }

    fn score_to_mode(score: f64) -> SessionMode {
        if score >= 0.85 {
            SessionMode::Revoked
        } else if score >= 0.6 {
            SessionMode::ReadOnly
        } else if score >= 0.3 {
            SessionMode::Shadow
        } else {
            SessionMode::Normal
        }
    }
}

impl Default for SessionRisk {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct RiskRegistry {
    sessions: DashMap<String, SessionRisk>,
}

impl RiskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&self, session_id: &str, event: RiskEvent) -> (f64, SessionMode) {
        // Insert if missing, then update — DashMap entry API is the cleanest
        let entry = self.sessions.entry(session_id.to_string()).or_default();
        entry.update(event)
    }

    pub fn current(&self, session_id: &str) -> (f64, SessionMode) {
        if let Some(s) = self.sessions.get(session_id) {
            (s.current_score(), s.current_mode())
        } else {
            (0.0, SessionMode::Normal)
        }
    }

    pub fn evict(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_normal() {
        let risk = SessionRisk::new();
        assert_eq!(risk.current_mode(), SessionMode::Normal);
        assert!(risk.can_write());
    }

    #[test]
    fn capability_denials_escalate() {
        let risk = SessionRisk::new();
        risk.update(RiskEvent::CapabilityDenial);
        assert_eq!(risk.current_mode(), SessionMode::Normal);
        risk.update(RiskEvent::CapabilityDenial);
        assert_eq!(risk.current_mode(), SessionMode::Shadow);
        risk.update(RiskEvent::CapabilityDenial);
        assert_eq!(risk.current_mode(), SessionMode::ReadOnly);
        risk.update(RiskEvent::CapabilityDenial);
        risk.update(RiskEvent::CapabilityDenial);
        assert_eq!(risk.current_mode(), SessionMode::Revoked);
    }

    #[test]
    fn successful_calls_decay() {
        let risk = SessionRisk::new();
        risk.update(RiskEvent::CapabilityDenial);
        risk.update(RiskEvent::CapabilityDenial);
        let (high, _) = risk.update(RiskEvent::CapabilityDenial);
        for _ in 0..50 {
            risk.update(RiskEvent::SuccessfulCall);
        }
        let (low, mode) = risk.update(RiskEvent::SuccessfulCall);
        assert!(low < high);
        assert_eq!(mode, SessionMode::Normal);
    }
}
