//! HATS Tier 1 Self-Registration
//!
//! At MCP server startup, register the server itself in the HATS governance
//! layer as an AI-facing endpoint. The proof ID is attached to subsequent
//! response headers (X-H33-HATS-Proof). H33 eats its own dog food — the
//! MCP server is the first HATS-certified AI-facing identity endpoint.
//!
//! HATS standard language: "HATS is a publicly available technical
//! conformance standard for continuous AI trustworthiness; certification
//! under HATS provides independently verifiable evidence that a system
//! satisfies the standard's defined controls."

use crate::client::H33ApiClient;
use crate::Result;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct HatsRegistration {
    pub proof_id: String,
    pub anchor_id: String,
    pub tier: u8,
    pub registered_at: String,
    pub certification_url: String,
}

impl HatsRegistration {
    pub fn proof_short(&self) -> String {
        self.proof_id.chars().take(16).collect()
    }

    pub fn anchor_short(&self) -> String {
        self.anchor_id.chars().take(16).collect()
    }
}

/// Register the MCP server session as a HATS Tier 1 endpoint.
/// Returns Ok(None) on graceful degradation (HATS layer unavailable),
/// which does NOT block server startup.
pub async fn register_mcp_with_hats(
    api: Arc<H33ApiClient>,
    session_id: &str,
    mcp_version: &str,
) -> Result<Option<HatsRegistration>> {
    let prompt_identity = serde_json::json!({
        "service": "h33-mcp",
        "version": mcp_version,
        "session_id": session_id,
        "role": "ai_facing_identity_endpoint",
        "registered_via": "hats_self_registration",
    });
    let response_metadata = serde_json::json!({
        "capabilities": [
            "substrate_anchor",
            "substrate_verify",
            "hats_register",
            "agent_identity_attestation",
            "hics_scan",
        ],
        "fraud_protection": [
            "epoch_evolved_nullifier",
            "behavioral_anomaly_detection",
            "binary_output_minimization",
            "dynamic_risk_scoring",
            "substrate_anchored_transcript",
        ],
    });

    let prompt_hash = hash_canonical(&prompt_identity);
    let response_hash = hash_canonical(&response_metadata);

    let result = api
        .anchor_ai_inference("0x08", &prompt_hash, &response_hash, "h33-mcp-self-registration")
        .await;

    match result {
        Ok((anchor_id, proof_id)) => {
            tracing::info!(
                "HATS registered · tier=1 · proof={} · anchor={}",
                &proof_id.chars().take(16).collect::<String>(),
                &anchor_id.chars().take(16).collect::<String>(),
            );
            Ok(Some(HatsRegistration {
                proof_id: proof_id.clone(),
                anchor_id,
                tier: 1,
                registered_at: chrono::Utc::now().to_rfc3339(),
                certification_url: format!("https://h33.ai/hats/proofs/{}", proof_id),
            }))
        }
        Err(e) => {
            // Graceful degradation — log a warning, don't block startup
            tracing::warn!("HATS self-registration failed: {}", e);
            Ok(None)
        }
    }
}

fn hash_canonical(v: &serde_json::Value) -> String {
    let s = v.to_string();
    let mut hasher = Sha3_256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}
