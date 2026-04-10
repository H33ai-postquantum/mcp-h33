//! Binary Output Information Minimization
//!
//! Patent Claim 127 (FraudShield absorption). Auth-boundary error responses
//! are reduced to the smallest signal needed for the caller to proceed.
//! In-session error responses stay verbose for legitimate agent debugging.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthBoundaryError {
    AuthFailed,
    Denied,
    SlowDown,
    NotFound,
    Duplicate,
    Unavailable,
}

impl AuthBoundaryError {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthBoundaryError::AuthFailed => "auth_failed",
            AuthBoundaryError::Denied => "denied",
            AuthBoundaryError::SlowDown => "slow_down",
            AuthBoundaryError::NotFound => "not_found",
            AuthBoundaryError::Duplicate => "duplicate",
            AuthBoundaryError::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MinimizedError {
    pub error: &'static str,
}

/// Minimize an auth-boundary error to its smallest binary signal.
pub fn minimize(err: AuthBoundaryError) -> MinimizedError {
    MinimizedError {
        error: err.as_str(),
    }
}
