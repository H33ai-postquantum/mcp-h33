//! H33 MCP Server — native Rust implementation
//!
//! This crate is the canonical Model Context Protocol server for H33.
//! It exposes the full H33 product surface — substrate primitive,
//! biometric authentication, ZK proofs, triple-key signing, BotShield,
//! HICS scoring, HATS governance — to MCP-capable AI coding agents.
//!
//! Architecture:
//!
//! ```text
//!   Claude Code  ──┐
//!   Cursor       ──┼──► h33-mcp (this crate, stdio JSON-RPC)
//!   Codex        ──┤        │
//!   Aider        ──┘        │
//!                           ▼
//!                    H33 Backend (Rust, Graviton4)
//!                    scif-backend + auth1-delivery-rs
//! ```
//!
//! Every tool dispatch flows through the FraudGuard (nullifier + risk +
//! anomaly + binary output minimization) and CacheeFlu (in-process
//! tool result cache, Patent Claim 126).
//!
//! See README.md for the architectural rule:
//!
//! > Agents hold cka_*. Servers hold ck_live_*. They are never the same thing.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![warn(missing_debug_implementations)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod cachee;
pub mod client;
pub mod config;
pub mod error;
pub mod fraud;
pub mod protocol;
pub mod server;
pub mod token;
pub mod tools;

pub use error::{Error, Result};

/// Server version, exposed to clients via the `initialize` MCP message.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SERVER_NAME: &str = "h33-mcp";
