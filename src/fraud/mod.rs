//! FraudGuard — anti-abuse layer for the MCP server.
//!
//! Implements the H33 Substrate Patent absorptions from FraudShield
//! (Claims 127–129) plus Extension 22 audit chain, applied to the MCP
//! server's own surface so H33 eats its own dog food:
//!
//!   - Patent Claim 127 — binary output information minimization (`responses`)
//!   - Patent Claim 128 — encrypted velocity + behavioral anomaly (`anomaly`)
//!   - Patent Claim 129 — epoch-evolved nullifier (`nullifier`)
//!   - Patent Extension 22 — substrate-anchored audit chain (`transcript`)
//!   - Customer webhook alert pipeline (`alerts`)
//!   - HATS Tier 1 self-registration (`hats`)
//!
//! Composed by `FraudGuard` in `guard.rs`.

pub mod alerts;
pub mod anomaly;
pub mod guard;
pub mod hats;
pub mod nullifier;
pub mod responses;
pub mod risk;
pub mod transcript;

pub use alerts::{AlertEvent, AlertPayload, AlertPipeline};
pub use anomaly::{AnomalyRegistry, AnomalySignal, SessionBaseline};
pub use guard::{FraudGuard, Verdict};
pub use hats::{register_mcp_with_hats, HatsRegistration};
pub use nullifier::{NullifierCache, NullifierResult};
pub use responses::{minimize, AuthBoundaryError};
pub use risk::{RiskRegistry, SessionMode, SessionRisk};
pub use transcript::SessionTranscript;
