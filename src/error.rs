//! Error types for the H33 MCP server.
//!
//! The error hierarchy splits into two categories:
//!   - Auth-boundary errors (returned to the client as binary-minimized MCP errors)
//!   - In-session errors (returned with full diagnostic detail to legitimate agents)
//!
//! The split is enforced by the `auth_boundary()` method which classifies
//! each error as either suitable for verbose response or requiring binary
//! minimization per Patent Claim 127 (FraudShield absorption).

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // ----- Auth-boundary errors (binary-minimized in responses) -----
    #[error("auth_failed")]
    AuthFailed,

    #[error("denied")]
    Denied,

    #[error("slow_down")]
    RateLimited,

    #[error("not_found")]
    NotFound,

    #[error("duplicate")]
    Duplicate,

    #[error("unavailable")]
    Unavailable,

    // ----- In-session errors (verbose detail allowed) -----
    #[error("token format invalid: {0}")]
    InvalidTokenFormat(String),

    #[error("token expired at {0}")]
    TokenExpired(String),

    #[error("token revoked")]
    TokenRevoked,

    #[error("missing capability: {0}")]
    MissingCapability(String),

    #[error("tenant isolation violation")]
    TenantIsolationViolation,

    #[error("MCP protocol error: {0}")]
    Protocol(String),

    #[error("JSON-RPC error: {0}")]
    JsonRpc(String),

    #[error("H33 API request failed: {0}")]
    ApiRequest(String),

    #[error("H33 API returned {status}: {body}")]
    ApiResponse { status: u16, body: String },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("HICS scan failed: {0}")]
    HicsScan(String),

    #[error("HATS registration failed: {0}")]
    HatsRegistration(String),

    #[error("transcript anchor commit failed: {0}")]
    TranscriptCommit(String),

    #[error("webhook delivery failed: {0}")]
    WebhookDelivery(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Returns true if this error should be binary-minimized when returned
    /// to a client whose token has not yet been fully verified. Patent Claim 127.
    pub fn is_auth_boundary(&self) -> bool {
        matches!(
            self,
            Error::AuthFailed
                | Error::Denied
                | Error::RateLimited
                | Error::NotFound
                | Error::Duplicate
                | Error::Unavailable
        )
    }

    /// Returns the binary error code for auth-boundary errors.
    /// Verbose errors return their full message instead.
    pub fn binary_code(&self) -> &'static str {
        match self {
            Error::AuthFailed => "auth_failed",
            Error::Denied | Error::MissingCapability(_) | Error::TokenRevoked => "denied",
            Error::RateLimited => "slow_down",
            Error::NotFound => "not_found",
            Error::Duplicate => "duplicate",
            Error::Unavailable => "unavailable",
            Error::TokenExpired(_) | Error::InvalidTokenFormat(_) => "auth_failed",
            Error::TenantIsolationViolation => "denied",
            _ => "internal_error",
        }
    }
}
