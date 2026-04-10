//! Typed reqwest client for the H33 backend API.
//!
//! Every MCP tool dispatch routes through this client. All requests
//! authenticate with the agent's `cka_*` token. Responses are deserialized
//! into `serde_json::Value` for forwarding to the MCP client; tool-specific
//! response shapes live in the tool modules themselves.

use crate::{Error, Result};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = concat!("h33-mcp/", env!("CARGO_PKG_VERSION"));

#[derive(Debug)]
pub struct H33ApiClient {
    client: Client,
    api_base: String,
    agent_token: String,
}

impl H33ApiClient {
    pub fn new(api_base: impl Into<String>, agent_token: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .map_err(Error::from)?;
        Ok(Self {
            client,
            api_base: api_base.into(),
            agent_token: agent_token.into(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.api_base.trim_end_matches('/'), path)
    }

    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// Health check — public, no auth required.
    pub async fn health(&self) -> Result<Value> {
        let url = self.url("/health");
        let res = self.client.get(&url).send().await?;
        check_status(&res)?;
        let body = res.json::<Value>().await?;
        Ok(body)
    }

    // ----- substrate -----

    pub async fn substrate_enroll(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/substrate/enroll", body).await
    }

    pub async fn substrate_verify(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/substrate/verify", body).await
    }

    pub async fn substrate_attest(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/substrate/attest", body).await
    }

    pub async fn substrate_revoke(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/substrate/revoke", body).await
    }

    pub async fn substrate_list_domains(&self) -> Result<Value> {
        self.get_json("/v1/substrate/domains").await
    }

    /// Convenience helper used by the substrate transcript module.
    /// Wraps a JSON payload, base64-encodes it, and POSTs to /v1/substrate/enroll
    /// with the given domain identifier.
    pub async fn substrate_enroll_json(
        &self,
        domain: &str,
        payload: &Value,
        purpose: Option<&str>,
    ) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let json_str = serde_json::to_string(payload)?;
        let artifact = STANDARD.encode(json_str.as_bytes());
        let body = serde_json::json!({
            "domain": domain,
            "artifact": artifact,
            "artifact_encoding": "base64",
            "metadata": purpose.map(|p| serde_json::json!({"purpose": p})),
        });
        let response = self.substrate_enroll(body).await?;
        response
            .get("id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| Error::ApiResponse {
                status: 200,
                body: "missing 'id' in substrate enroll response".into(),
            })
    }

    /// AI inference anchor — produces both a substrate anchor and a HATS proof.
    /// Returns (anchor_id, hats_proof_id) — used by the HATS self-registration path.
    pub async fn anchor_ai_inference(
        &self,
        domain: &str,
        prompt_hash: &str,
        response_hash: &str,
        model: &str,
    ) -> Result<(String, String)> {
        let body = serde_json::json!({
            "domain": domain,
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "model": model,
        });
        let result = self.anchor_ai_inference_raw(body).await?;
        let anchor_id = result
            .pointer("/anchor/id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| Error::ApiResponse {
                status: 200,
                body: "missing /anchor/id".into(),
            })?;
        let proof_id = result
            .pointer("/hats_proof/id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| Error::ApiResponse {
                status: 200,
                body: "missing /hats_proof/id".into(),
            })?;
        Ok((anchor_id, proof_id))
    }

    /// Raw AI inference anchor — used by the MCP tool which forwards the
    /// full response (anchor + hats_proof) back to the agent.
    pub async fn anchor_ai_inference_raw(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/substrate/anchor_ai_inference", body).await
    }

    // ----- tenant -----

    pub async fn tenant_read(&self) -> Result<Value> {
        self.get_json("/v1/tenant").await
    }

    pub async fn tenant_quota(&self) -> Result<Value> {
        self.get_json("/v1/tenant/quota").await
    }

    // ----- audit -----

    pub async fn audit_read(&self, query: &str) -> Result<Value> {
        let path = if query.is_empty() {
            "/v1/audit".to_string()
        } else {
            format!("/v1/audit?{}", query)
        };
        self.get_json(&path).await
    }

    // ----- HICS -----

    pub async fn hics_scan(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/hics/scan", body).await
    }

    pub async fn hics_verify(&self, proof_id: &str) -> Result<Value> {
        self.get_json(&format!("/v1/hics/verify/{}", proof_id)).await
    }

    // ----- biometrics (Tier 1) -----

    pub async fn biometric_enroll(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/biometric/enroll", body).await
    }

    pub async fn biometric_verify(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/biometric/verify", body).await
    }

    // ----- ZK (Tier 1) -----

    pub async fn zk_prove(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/zk/prove", body).await
    }

    pub async fn zk_verify(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/zk/verify", body).await
    }

    // ----- Triple-key signing (Tier 1) -----

    pub async fn triple_key_sign(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/triple_key/sign", body).await
    }

    pub async fn triple_key_verify(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/triple_key/verify", body).await
    }

    // ----- BotShield (Tier 1) -----

    pub async fn botshield_challenge(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/botshield/challenge", body).await
    }

    pub async fn botshield_verify(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/botshield/verify", body).await
    }

    // ----- Bitcoin UTXO attestation -----
    //
    // Three-family post-quantum signatures (Dilithium + FALCON + SPHINCS+)
    // anchored permanently to Arweave, with a 32-byte commitment + 42-byte
    // retrieval pointer = 74 bytes total, fitting in Bitcoin's OP_RETURN.
    //
    // The verify and lookup endpoints are public (no auth required) so any
    // party can verify a previously-issued attestation without an H33 account.

    pub async fn bitcoin_attest(&self, body: Value) -> Result<Value> {
        self.post_json("/v1/bitcoin/attest", body).await
    }

    pub async fn bitcoin_verify(&self, attestation_id: &str) -> Result<Value> {
        self.get_json(&format!("/v1/bitcoin/verify/{}", attestation_id))
            .await
    }

    pub async fn bitcoin_lookup(&self, utxo: &str) -> Result<Value> {
        // utxo format: "txid:vout"
        self.get_json(&format!(
            "/v1/bitcoin/lookup?utxo={}",
            urlencoding(utxo)
        ))
        .await
    }

    // ----- Internal helpers -----

    async fn post_json(&self, path: &str, body: Value) -> Result<Value> {
        let url = self.url(path);
        let res = self
            .client
            .post(&url)
            .bearer_auth(&self.agent_token)
            .json(&body)
            .send()
            .await?;
        check_status(&res)?;
        let value = res.json::<Value>().await.unwrap_or(Value::Null);
        Ok(value)
    }

    async fn get_json(&self, path: &str) -> Result<Value> {
        let url = self.url(path);
        let res = self
            .client
            .get(&url)
            .bearer_auth(&self.agent_token)
            .send()
            .await?;
        check_status(&res)?;
        let value = res.json::<Value>().await.unwrap_or(Value::Null);
        Ok(value)
    }
}

fn check_status(res: &reqwest::Response) -> Result<()> {
    let status = res.status();
    if status.is_success() || status == StatusCode::NO_CONTENT {
        return Ok(());
    }
    Err(match status {
        StatusCode::UNAUTHORIZED => Error::AuthFailed,
        StatusCode::FORBIDDEN => Error::Denied,
        StatusCode::TOO_MANY_REQUESTS => Error::RateLimited,
        StatusCode::NOT_FOUND => Error::NotFound,
        StatusCode::SERVICE_UNAVAILABLE => Error::Unavailable,
        _ => Error::ApiResponse {
            status: status.as_u16(),
            body: status.canonical_reason().unwrap_or("unknown").to_string(),
        },
    })
}

/// Minimal URL-encoding for query string values. Encodes everything that
/// isn't unreserved (RFC 3986 section 2.3) plus the colon (which Bitcoin
/// UTXO syntax uses as `txid:vout`). Sufficient for the lookup endpoint.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            for b in c.to_string().as_bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}
