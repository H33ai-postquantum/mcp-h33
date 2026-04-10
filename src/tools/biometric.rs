//! Biometric tools — H33-128 encrypted biometric authentication.
//!
//! Two tools:
//!   - h33_biometric_enroll — enroll a user under FHE, returns substrate anchor
//!   - h33_biometric_verify — verify a probe template against an enrolled user
//!
//! The H33 flagship. 35.25 µs per auth, 2.21M auth/sec sustained on
//! Graviton4. Every authentication result is a substrate-anchored
//! attestation bound at domain identifier 0x01 (BIOMETRIC_AUTH).

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{schema_enum, schema_object, schema_string, ToolInputSchema};
use crate::token::Capability;
use serde_json::Value;
use std::sync::Arc;

pub fn enroll() -> RegisteredTool {
    RegisteredTool {
        name: "h33_biometric_enroll".into(),
        description: "Enroll a new user's biometric template under FHE. The template is \
                      encrypted client-side and committed to a substrate anchor at \
                      domain identifier 0x01 (BIOMETRIC_AUTH). The server never sees \
                      the plaintext biometric. Supports fingerprint, face, and voice \
                      modalities. Returns the substrate anchor ID that serves as the \
                      user's PQ-attested biometric identity credential. Patent: \
                      Extension 1 biometric application of substrate primitive."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "user_id",
                schema_string("Tenant-scoped unique identifier for the user being enrolled"),
            )
            .property(
                "modality",
                schema_enum(
                    "Biometric modality",
                    &["fingerprint", "face", "voice"],
                ),
            )
            .property(
                "encrypted_template",
                schema_string(
                    "FHE-encrypted biometric template, base64-encoded. Client encrypts \
                     before submission; server never sees plaintext.",
                ),
            )
            .property("metadata", schema_object("Optional metadata bound to the anchor"))
            .require("user_id")
            .require("modality")
            .require("encrypted_template"),
        capability: Capability::BiometricEnroll,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.biometric_enroll(args).await })
        }),
    }
}

pub fn verify() -> RegisteredTool {
    RegisteredTool {
        name: "h33_biometric_verify".into(),
        description: "Verify a biometric probe template against an enrolled user. \
                      Runs the FHE inner product match on Graviton4 infrastructure \
                      (35.25 µs per auth). Returns the match result, similarity score, \
                      STARK proof of correct computation, and a new substrate anchor \
                      at domain 0x01 attesting this specific verification event. \
                      The probe is NEVER decrypted server-side."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "user_id",
                schema_string("Tenant-scoped user identifier previously enrolled"),
            )
            .property(
                "modality",
                schema_enum("Biometric modality", &["fingerprint", "face", "voice"]),
            )
            .property(
                "encrypted_probe",
                schema_string(
                    "FHE-encrypted probe template to verify against the enrolled user, \
                     base64-encoded",
                ),
            )
            .property(
                "threshold",
                schema_string(
                    "Optional similarity threshold (0.0 to 1.0). Default 0.9 for H33-128.",
                ),
            )
            .require("user_id")
            .require("modality")
            .require("encrypted_probe"),
        capability: Capability::BiometricVerify,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.biometric_verify(args).await })
        }),
    }
}
