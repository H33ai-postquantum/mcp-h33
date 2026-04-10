//! ZK proof tools — STARK lookup proofs with no trusted setup.
//!
//! Two tools:
//!   - h33_zk_prove  — generate a STARK proof for an arbitrary lookup claim
//!   - h33_zk_verify — verify an existing STARK proof
//!
//! The 192-byte proof, 0.2 µs verify path that underlies HICS, substrate
//! attestations, and every other H33 product requiring privacy-preserving
//! correctness attestation.

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{schema_object, schema_string, ToolInputSchema};
use crate::token::Capability;
use serde_json::Value;
use std::sync::Arc;

pub fn prove() -> RegisteredTool {
    RegisteredTool {
        name: "h33_zk_prove".into(),
        description: "Generate a ZK-STARK lookup proof for an arbitrary claim. \
                      No trusted setup required. Produces a 192-byte proof that \
                      verifies in ~0.2 microseconds. Use this to prove any \
                      'X without revealing Y' pattern. The H33 backend runs the \
                      prover; the client receives the proof bundle ready for \
                      distribution or anchoring to the substrate."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "statement",
                schema_string(
                    "The claim being proved, as a canonical string representation. \
                     The backend interprets this against the configured lookup tables.",
                ),
            )
            .property(
                "witness",
                schema_object(
                    "Private witness data for the prover. Never leaves the server; \
                     only the proof is returned.",
                ),
            )
            .property(
                "public_inputs",
                schema_object("Public inputs visible to both prover and verifier"),
            )
            .require("statement"),
        capability: Capability::ZkProve,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.zk_prove(args).await })
        }),
    }
}

pub fn verify() -> RegisteredTool {
    RegisteredTool {
        name: "h33_zk_verify".into(),
        description: "Verify an existing ZK-STARK proof. Read-only, cacheable, \
                      ~0.2 microsecond verification latency. Takes the proof bundle \
                      returned from h33_zk_prove and the public inputs; returns \
                      valid/invalid plus a verification substrate anchor."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "proof",
                schema_string("The STARK proof bundle, base64-encoded"),
            )
            .property(
                "public_inputs",
                schema_object("Public inputs to verify the proof against"),
            )
            .require("proof")
            .require("public_inputs"),
        capability: Capability::ZkVerify,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.zk_verify(args).await })
        }),
    }
}
