//! MCP tool registry and dispatch.
//!
//! Each tool is a unit of agent intent — "wrap classical crypto",
//! "verify an anchor", "scan my codebase", etc. Tools are composed into
//! the registry at startup and dispatched by the server's call_tool handler.
//!
//! Capability mapping:
//!   - Each tool declares the cka_* token capability bit it requires
//!   - The dispatcher rejects with `denied` if the bit is not set
//!
//! Cache mapping:
//!   - Read-only tools are cached by CacheeFlu (Patent Claim 126)
//!   - Write tools bypass the cache entirely
//!
//! All tools flow through the FraudGuard (nullifier + risk + anomaly +
//! binary minimization) before reaching the dispatch handler in this module.

pub mod biometric;
pub mod bitcoin;
pub mod botshield;
pub mod hics;
pub mod meta;
pub mod registry;
pub mod substrate;
pub mod tenant;
pub mod triple_key;
pub mod zk;

pub use registry::{build_full_registry, ToolContext, ToolHandler, ToolRegistry};
