//! Agent capability token format and verification.
//!
//! See `docs/agent-token-architecture.md` in h33-deploy-correct for the
//! full design rationale. The architectural rule:
//!
//! > Agents hold cka_*. Servers hold ck_live_*. They are never the same thing.

pub mod cka;

pub use cka::{AgentToken, Capability, Environment, TokenError};
