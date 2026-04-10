//! In-process tool result cache.
//!
//! Patent context: this implements the CacheeFlu pattern from H33 Substrate
//! Patent Claim 126 — an in-process cryptographic verification cache distinct
//! from the external high-speed verification cache. CacheeFlu shares the
//! two-tier W-TinyLFU eviction architecture but is independently implemented
//! and tuned for MCP tool dispatch workloads.

pub mod flu;

pub use flu::{CacheeFlu, CacheStats};
