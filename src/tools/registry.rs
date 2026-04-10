//! Tool registry — the central dispatch table for MCP tool calls.
//!
//! Each tool is registered with:
//!   - A name (h33_substrate_enroll, h33_hics_scan, etc.)
//!   - A description (shown to the agent in tools/list)
//!   - An input schema (JSON Schema fragment)
//!   - A capability bit (which cka_* token capability is required)
//!   - A handler closure (async fn taking args, returning a Result<Value>)

use crate::cachee::CacheeFlu;
use crate::client::H33ApiClient;
use crate::fraud::FraudGuard;
use crate::protocol::messages::{Tool, ToolInputSchema};
use crate::token::Capability;
use crate::Result;
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Shared context handed to every tool handler.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub api: Arc<H33ApiClient>,
    pub cachee: Arc<CacheeFlu>,
    pub fraud_guard: Arc<FraudGuard>,
}

/// Async handler signature. Takes the JSON args and returns a JSON result.
pub type ToolFuture = Pin<Box<dyn Future<Output = Result<Value>> + Send>>;
pub type ToolHandler =
    Arc<dyn Fn(ToolContext, Value) -> ToolFuture + Send + Sync + 'static>;

#[derive(Clone)]
pub struct RegisteredTool {
    pub name: String,
    pub description: String,
    pub input_schema: ToolInputSchema,
    pub capability: Capability,
    pub handler: ToolHandler,
}

impl std::fmt::Debug for RegisteredTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredTool")
            .field("name", &self.name)
            .field("capability", &self.capability)
            .finish()
    }
}

pub struct ToolRegistry {
    tools: HashMap<String, RegisteredTool>,
}

impl std::fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolRegistry")
            .field("tool_count", &self.tools.len())
            .finish()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: RegisteredTool) {
        self.tools.insert(tool.name.clone(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools.get(name)
    }

    pub fn list(&self) -> Vec<Tool> {
        let mut out: Vec<Tool> = self
            .tools
            .values()
            .map(|t| Tool {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.input_schema.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn count(&self) -> usize {
        self.tools.len()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the complete tool registry with all 20 tools registered.
/// Foundation tools + Tier 1 product tools.
pub fn build_full_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();

    // Substrate (5)
    r.register(super::substrate::enroll());
    r.register(super::substrate::verify());
    r.register(super::substrate::attest());
    r.register(super::substrate::list_domains());
    r.register(super::substrate::anchor_ai_inference());

    // Tenant (2)
    r.register(super::tenant::read());
    r.register(super::tenant::read_usage());

    // Audit (1)
    r.register(super::tenant::audit_read());

    // Meta (2)
    r.register(super::meta::detection_rules());
    r.register(super::meta::get_manifest());

    // HICS (2)
    r.register(super::hics::scan());
    r.register(super::hics::badge());

    // Biometric (Tier 1, 2)
    r.register(super::biometric::enroll());
    r.register(super::biometric::verify());

    // ZK (Tier 1, 2)
    r.register(super::zk::prove());
    r.register(super::zk::verify());

    // Triple-key signing (Tier 1, 2)
    r.register(super::triple_key::sign());
    r.register(super::triple_key::verify());

    // BotShield (Tier 1, 2)
    r.register(super::botshield::challenge());
    r.register(super::botshield::verify());

    // Bitcoin UTXO quantum insurance (3 tools)
    r.register(super::bitcoin::attest());
    r.register(super::bitcoin::verify());
    r.register(super::bitcoin::lookup());

    r
}
