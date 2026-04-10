//! Meta tools — detection rules YAML and agent manifest JSON.
//!
//! Both tools fetch public resources from h33.ai and cache heavily.
//! They help agents self-discover the full H33 surface before making
//! any authenticated calls.

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::ToolInputSchema;
use crate::token::Capability;
use crate::Result;
use serde_json::Value;
use std::sync::Arc;

const DETECTION_RULES_URL: &str = "https://h33.ai/detection-rules.yaml";
const MANIFEST_URL: &str = "https://h33.ai/.well-known/h33-agent-manifest.json";

pub fn detection_rules() -> RegisteredTool {
    RegisteredTool {
        name: "h33_detection_rules".into(),
        description: "Fetch the complete H33 detection rules YAML. Use this at the \
                      START of an integration session to grep the customer's codebase \
                      for classical crypto patterns that need substrate wrapping. \
                      Returns 41+ rules across 16 categories covering JWT, RSA, TLS, \
                      AI inference, database, audit, backup, HSM, messaging, document \
                      signing, supply chain, blockchain, and framework integration. \
                      Read-only public data; heavily cached."
            .into(),
        input_schema: ToolInputSchema::object(),
        capability: Capability::McpConnect,
        handler: Arc::new(|_ctx: ToolContext, _args: Value| {
            Box::pin(async move { fetch_text(DETECTION_RULES_URL).await })
        }),
    }
}

pub fn get_manifest() -> RegisteredTool {
    RegisteredTool {
        name: "h33_get_manifest".into(),
        description: "Fetch the H33 agent manifest describing all capabilities, \
                      domain identifiers, safety rules, and the substrate primitive \
                      structure. Read this once at session start to understand the \
                      full H33 API surface. Returns a machine-readable JSON document."
            .into(),
        input_schema: ToolInputSchema::object(),
        capability: Capability::McpConnect,
        handler: Arc::new(|_ctx: ToolContext, _args: Value| {
            Box::pin(async move { fetch_json(MANIFEST_URL).await })
        }),
    }
}

async fn fetch_text(url: &str) -> Result<Value> {
    let res = reqwest::Client::new()
        .get(url)
        .header("User-Agent", concat!("h33-mcp/", env!("CARGO_PKG_VERSION")))
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(crate::Error::ApiResponse {
            status: res.status().as_u16(),
            body: res.status().canonical_reason().unwrap_or("error").into(),
        });
    }
    let text = res.text().await?;
    Ok(Value::String(text))
}

async fn fetch_json(url: &str) -> Result<Value> {
    let res = reqwest::Client::new()
        .get(url)
        .header("User-Agent", concat!("h33-mcp/", env!("CARGO_PKG_VERSION")))
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(crate::Error::ApiResponse {
            status: res.status().as_u16(),
            body: res.status().canonical_reason().unwrap_or("error").into(),
        });
    }
    let v = res.json::<Value>().await?;
    Ok(v)
}
