//! Triple-key signing tools — H33-3-Key nested post-quantum signatures.
//!
//! Two tools:
//!   - h33_triple_key_sign   — nested Ed25519 + Dilithium-5 + FALCON-512 signature
//!   - h33_triple_key_verify — verify a triple-key signature anchor
//!
//! The marquee H33 product. Produces a 32-byte on-chain commitment plus
//! 42-byte retrieval pointer = 74 bytes total, fitting inside Bitcoin's
//! 80-byte OP_RETURN with 6 bytes to spare. Three distinct mathematical
//! families (classical EC, module-lattice, NTRU-lattice); a quantum
//! adversary has to break all three independently.

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{schema_string, ToolInputSchema};
use crate::token::Capability;
use serde_json::Value;
use std::sync::Arc;

pub fn sign() -> RegisteredTool {
    RegisteredTool {
        name: "h33_triple_key_sign".into(),
        description: "Sign a message with the H33 triple-key nested post-quantum \
                      signature scheme: Ed25519 + Dilithium-5 (ML-DSA-87) + FALCON-512. \
                      The combined ~33 KB of raw signature material is compressed to a \
                      32-byte SHA3-256 commitment plus 42-byte retrieval pointer = \
                      74 bytes total, fitting in Bitcoin's OP_RETURN. Returns the \
                      74-byte anchor ID ready for on-chain inclusion, plus the full \
                      signature bundle stored in the high-speed verification cache. \
                      This is the canonical Bitcoin post-quantum signing surface."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "message",
                schema_string("Message bytes to sign, base64-encoded"),
            )
            .property(
                "signer_key_id",
                schema_string(
                    "Signer's key identifier from the tenant's H33 key management. \
                     If omitted, uses the tenant's default signing key.",
                ),
            ),
        capability: Capability::TripleKeySign,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.triple_key_sign(args).await })
        }),
    }
}

pub fn verify() -> RegisteredTool {
    RegisteredTool {
        name: "h33_triple_key_verify".into(),
        description: "Verify a 74-byte triple-key anchor by retrieving the full \
                      signature bundle from the high-speed verification cache and \
                      validating each of the three signatures against the signer's \
                      public keys. Returns valid/invalid per family plus an overall \
                      verdict. Single cache lookup + hash recomputation; no need to \
                      re-execute each PQ verification independently unless requested."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "anchor_id",
                schema_string("The 74-byte anchor ID from h33_triple_key_sign"),
            )
            .property(
                "message",
                schema_string("Original message bytes (base64) for signature verification"),
            )
            .require("anchor_id")
            .require("message"),
        capability: Capability::TripleKeyVerify,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.triple_key_verify(args).await })
        }),
    }
}
