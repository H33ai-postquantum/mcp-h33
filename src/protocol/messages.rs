//! MCP-specific message types layered on top of JSON-RPC 2.0.
//!
//! Reference: <https://spec.modelcontextprotocol.io/specification/>

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: Value,
    #[serde(rename = "clientInfo", default)]
    pub client_info: Option<ClientInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    pub capabilities: ServerCapabilities,
    /// H33 extensions exposed to the client at handshake time.
    /// Includes the HATS proof ID once registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ServerCapabilities {
    pub tools: ToolsCapability,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ToolsCapability {
    /// Whether the server supports tool list change notifications.
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

// ---------------------------------------------------------------------------
// tools/list
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ListToolsResult {
    pub tools: Vec<Tool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: ToolInputSchema,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolInputSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    pub properties: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

impl ToolInputSchema {
    pub fn object() -> Self {
        Self {
            schema_type: "object".to_string(),
            properties: BTreeMap::new(),
            required: Vec::new(),
        }
    }

    pub fn property(mut self, name: &str, schema: Value) -> Self {
        self.properties.insert(name.to_string(), schema);
        self
    }

    pub fn require(mut self, name: &str) -> Self {
        self.required.push(name.to_string());
        self
    }
}

// ---------------------------------------------------------------------------
// tools/call
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallToolParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallToolResult {
    pub content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

impl CallToolResult {
    pub fn success_text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::text(text)],
            is_error: false,
        }
    }

    pub fn error_text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::text(text)],
            is_error: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ToolContent {
    Text { text: String },
}

impl ToolContent {
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }
}

/// Helper for building JSON Schema input definitions.
pub fn schema_string(description: &str) -> Value {
    serde_json::json!({"type": "string", "description": description})
}

pub fn schema_string_pattern(description: &str, pattern: &str) -> Value {
    serde_json::json!({
        "type": "string",
        "description": description,
        "pattern": pattern,
    })
}

pub fn schema_object(description: &str) -> Value {
    serde_json::json!({"type": "object", "description": description})
}

pub fn schema_integer(description: &str, default: Option<i64>) -> Value {
    if let Some(d) = default {
        serde_json::json!({"type": "integer", "description": description, "default": d})
    } else {
        serde_json::json!({"type": "integer", "description": description})
    }
}

pub fn schema_number(description: &str) -> Value {
    serde_json::json!({"type": "number", "description": description})
}

pub fn schema_boolean(description: &str, default: bool) -> Value {
    serde_json::json!({"type": "boolean", "description": description, "default": default})
}

pub fn schema_enum(description: &str, values: &[&str]) -> Value {
    serde_json::json!({
        "type": "string",
        "description": description,
        "enum": values,
    })
}

pub fn schema_array(description: &str, item_type: &str) -> Value {
    serde_json::json!({
        "type": "array",
        "description": description,
        "items": {"type": item_type},
    })
}
