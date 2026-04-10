//! Tenant and audit tools.
//!
//! Three tools: read tenant metadata, read quota/usage, read agent audit log.

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{schema_integer, schema_string, ToolInputSchema};
use crate::token::Capability;
use serde_json::Value;
use std::sync::Arc;

pub fn read() -> RegisteredTool {
    RegisteredTool {
        name: "h33_tenant_read".into(),
        description: "Read the current tenant's metadata (id, name, tier, status). \
                      Read-only, cacheable, always safe."
            .into(),
        input_schema: ToolInputSchema::object(),
        capability: Capability::TenantRead,
        handler: Arc::new(|ctx: ToolContext, _args: Value| {
            Box::pin(async move { ctx.api.tenant_read().await })
        }),
    }
}

pub fn read_usage() -> RegisteredTool {
    RegisteredTool {
        name: "h33_tenant_read_usage".into(),
        description: "Read current tenant quota and usage for the billing period. \
                      Read-only, cacheable."
            .into(),
        input_schema: ToolInputSchema::object(),
        capability: Capability::TenantReadUsage,
        handler: Arc::new(|ctx: ToolContext, _args: Value| {
            Box::pin(async move { ctx.api.tenant_quota().await })
        }),
    }
}

pub fn audit_read() -> RegisteredTool {
    RegisteredTool {
        name: "h33_audit_read".into(),
        description: "Read recent audit log entries for this agent session. \
                      Shows every action the agent has taken with full attribution \
                      to the authorizing human. Read-only."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "since",
                schema_string("Optional ISO 8601 timestamp — only return entries after this time"),
            )
            .property(
                "limit",
                schema_integer("Maximum entries to return (default 100, max 1000)", Some(100)),
            ),
        capability: Capability::AuditRead,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move {
                let mut parts: Vec<String> = Vec::new();
                if let Some(s) = args.get("since").and_then(|v| v.as_str()) {
                    parts.push(format!("since={}", urlencoding(s)));
                }
                if let Some(l) = args.get("limit").and_then(|v| v.as_u64()) {
                    parts.push(format!("limit={}", l));
                }
                let query = parts.join("&");
                ctx.api.audit_read(&query).await
            })
        }),
    }
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}
