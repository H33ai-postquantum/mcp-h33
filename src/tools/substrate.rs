//! Substrate tools — the canonical commitment substrate primitive.
//!
//! Five tools:
//!   - h33_substrate_enroll              (write, Capability::SubstrateEnroll)
//!   - h33_substrate_verify              (read,  Capability::SubstrateVerify)
//!   - h33_substrate_attest              (write, Capability::SubstrateAttest)
//!   - h33_substrate_list_domains        (read,  Capability::SubstrateListDomains)
//!   - h33_substrate_anchor_ai_inference (write, Capability::SubstrateAnchorAiInference)

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{
    schema_enum, schema_object, schema_string, schema_string_pattern, ToolInputSchema,
};
use crate::token::Capability;
use serde_json::Value;
use std::sync::Arc;

const DOMAIN_PATTERN: &str = "^0x[0-9A-Fa-f]{2}$";

pub fn enroll() -> RegisteredTool {
    RegisteredTool {
        name: "h33_substrate_enroll".into(),
        description: "Create a new canonical commitment substrate anchor for an artifact. \
                      Returns a 74-byte anchor ID (32-byte SHA3-256 commitment + 42-byte \
                      retrieval pointer). Use this to wrap classical crypto (JWT, RSA sig, \
                      TLS handshake) with post-quantum binding. Patent: substrate primitive."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "domain",
                schema_string_pattern(
                    "H33 registry domain identifier, e.g. 0x16 (API_REQUEST). \
                     Call h33_substrate_list_domains for the full list.",
                    DOMAIN_PATTERN,
                ),
            )
            .property(
                "artifact",
                schema_string("The artifact bytes to anchor, base64-encoded by default"),
            )
            .property(
                "artifact_encoding",
                schema_enum(
                    "Encoding of the artifact field",
                    &["base64", "hex", "utf8"],
                ),
            )
            .property("metadata", schema_object("Optional metadata kept with the anchor"))
            .require("domain")
            .require("artifact"),
        capability: Capability::SubstrateEnroll,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.substrate_enroll(args).await })
        }),
    }
}

pub fn verify() -> RegisteredTool {
    RegisteredTool {
        name: "h33_substrate_verify".into(),
        description: "Verify an existing substrate anchor. Read-only, always safe. \
                      Returns validity, domain, age, and creation timestamp."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "anchor_id",
                schema_string("The 74-byte anchor ID returned from h33_substrate_enroll"),
            )
            .property(
                "expected_domain",
                schema_string_pattern(
                    "Optional: fail unless the anchor's domain matches this value",
                    DOMAIN_PATTERN,
                ),
            )
            .require("anchor_id"),
        capability: Capability::SubstrateVerify,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.substrate_verify(args).await })
        }),
    }
}

pub fn attest() -> RegisteredTool {
    RegisteredTool {
        name: "h33_substrate_attest".into(),
        description: "Generate a fresh attestation for an artifact even if a prior \
                      anchor exists. Used for periodic re-attestation workflows."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "domain",
                schema_string_pattern("H33 registry domain identifier", DOMAIN_PATTERN),
            )
            .property("artifact", schema_string("Artifact bytes (base64)"))
            .property(
                "artifact_encoding",
                schema_enum("Encoding", &["base64", "hex", "utf8"]),
            )
            .property("metadata", schema_object("Optional metadata"))
            .require("domain")
            .require("artifact"),
        capability: Capability::SubstrateAttest,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.substrate_attest(args).await })
        }),
    }
}

pub fn list_domains() -> RegisteredTool {
    RegisteredTool {
        name: "h33_substrate_list_domains".into(),
        description: "List all 95 registry domain identifiers. Read-only. \
                      Use this to discover the right domain for a given computation \
                      category before calling h33_substrate_enroll."
            .into(),
        input_schema: ToolInputSchema::object(),
        capability: Capability::SubstrateListDomains,
        handler: Arc::new(|ctx: ToolContext, _args: Value| {
            Box::pin(async move { ctx.api.substrate_list_domains().await })
        }),
    }
}

pub fn anchor_ai_inference() -> RegisteredTool {
    RegisteredTool {
        name: "h33_substrate_anchor_ai_inference".into(),
        description: "Anchor an AI inference AND register HATS Tier 1 governance in one \
                      call. Use this whenever you wrap a call to OpenAI, Anthropic, Google, \
                      or local LLM inference. Two compliance requirements (PQ security + \
                      HATS AI trust) solved in one API call."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "domain",
                schema_enum(
                    "AI-related domain identifier (0x37 LLM_INFERENCE is most common)",
                    &["0x08", "0x33", "0x34", "0x35", "0x36", "0x37", "0x45", "0x46", "0x47"],
                ),
            )
            .property(
                "prompt_hash",
                schema_string("SHA3-256 of the canonical prompt representation, hex"),
            )
            .property(
                "response_hash",
                schema_string("SHA3-256 of the canonical model response, hex"),
            )
            .property(
                "model",
                schema_string("Model identifier, e.g. 'gpt-4', 'claude-opus-4-6'"),
            )
            .property("metadata", schema_object("Optional metadata"))
            .require("domain")
            .require("prompt_hash")
            .require("response_hash")
            .require("model"),
        capability: Capability::SubstrateAnchorAiInference,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.anchor_ai_inference_raw(args).await })
        }),
    }
}
