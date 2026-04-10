//! Runtime configuration for the H33 MCP server.
//!
//! Sources, in priority order:
//!   1. Command-line flags (clap)
//!   2. Environment variables (H33_*)
//!   3. Defaults
//!
//! No config files. Stateless. Every config value visible at startup.

use clap::Parser;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "h33-mcp",
    version,
    about = "H33 Model Context Protocol server — native Rust",
    long_about = "Exposes H33 post-quantum substrate, biometrics, ZK, triple-key signing, BotShield, HICS, and HATS to Claude Code, Cursor, Codex, Aider, and other MCP-capable AI agents.\n\nThe canonical surface for H33. Patent pending."
)]
pub struct CliArgs {
    /// H33 API base URL (sandbox by default)
    #[arg(long, env = "H33_API_BASE", default_value = "https://sandbox.api.h33.ai")]
    pub api_base: String,

    /// Agent capability token (cka_*). Must NOT be a ck_live_* key.
    #[arg(long, env = "H33_AGENT_TOKEN", hide_env_values = true)]
    pub agent_token: String,

    /// Optional customer webhook URL for fraud alerts
    #[arg(long, env = "H33_WEBHOOK_URL")]
    pub webhook_url: Option<String>,

    /// HMAC secret for webhook signing (defaults to a per-process random value)
    #[arg(long, env = "H33_WEBHOOK_SECRET", hide_env_values = true)]
    pub webhook_secret: Option<String>,

    /// Local salt for nullifier session secret derivation. Defaults to a
    /// fresh per-process UUID, which means captured nullifiers cannot be
    /// replayed against a different MCP server instance.
    #[arg(long, env = "H33_MCP_LOCAL_SALT", hide_env_values = true)]
    pub local_salt: Option<String>,

    /// Override the session ID (defaults to a fresh UUIDv7 per process).
    #[arg(long, env = "H33_MCP_SESSION_ID")]
    pub session_id: Option<String>,

    /// Substrate transcript flush period in seconds (default 60s).
    #[arg(long, env = "H33_TRANSCRIPT_PERIOD_SECONDS", default_value_t = 60)]
    pub transcript_period_seconds: u64,

    /// Disable substrate-anchored session transcripts (Extension 22).
    /// Useful in testing; not recommended in production.
    #[arg(long, env = "H33_DISABLE_TRANSCRIPT", default_value_t = false)]
    pub disable_transcript: bool,

    /// Disable HATS Tier 1 self-registration on startup.
    #[arg(long, env = "H33_DISABLE_HATS", default_value_t = false)]
    pub disable_hats: bool,

    /// Logging level (uses RUST_LOG-style filter)
    #[arg(long, env = "H33_LOG", default_value = "info")]
    pub log: String,
}

/// Resolved runtime configuration after CLI parsing and default fill-in.
#[derive(Debug, Clone)]
pub struct Config {
    pub api_base: String,
    pub agent_token: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: String,
    pub local_salt: String,
    pub session_id: String,
    pub transcript_period_seconds: u64,
    pub disable_transcript: bool,
    pub disable_hats: bool,
    pub log: String,
}

impl Config {
    /// Build a Config from CLI args, generating UUIDs for any unset fields.
    pub fn from_args(args: CliArgs) -> Self {
        Self {
            api_base: args.api_base,
            agent_token: args.agent_token,
            webhook_url: args.webhook_url,
            webhook_secret: args
                .webhook_secret
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            local_salt: args
                .local_salt
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            session_id: args
                .session_id
                .unwrap_or_else(|| Uuid::now_v7().to_string()),
            transcript_period_seconds: args.transcript_period_seconds,
            disable_transcript: args.disable_transcript,
            disable_hats: args.disable_hats,
            log: args.log,
        }
    }

    /// Validate that the agent token is well-formed (cka_* prefix only).
    /// Refuses ck_live_* and ck_test_* keys explicitly.
    pub fn validate(&self) -> crate::Result<()> {
        if self.agent_token.is_empty() {
            return Err(crate::Error::InvalidTokenFormat(
                "H33_AGENT_TOKEN is empty. Mint one with: h33 mint".into(),
            ));
        }
        if self.agent_token.starts_with("ck_live_") || self.agent_token.starts_with("ck_test_") {
            return Err(crate::Error::InvalidTokenFormat(
                "H33_AGENT_TOKEN must be a cka_* agent capability token. \
                 ck_live_* and ck_test_* keys are NEVER safe in agent contexts. \
                 Mint a cka_* token with: h33 mint"
                    .into(),
            ));
        }
        if !self.agent_token.starts_with("cka_") {
            return Err(crate::Error::InvalidTokenFormat(
                "H33_AGENT_TOKEN must start with 'cka_'. See docs/agent-token-architecture.md".into(),
            ));
        }
        Ok(())
    }
}

/// Shared, immutable runtime configuration handed to every server module.
pub type SharedConfig = Arc<Config>;
