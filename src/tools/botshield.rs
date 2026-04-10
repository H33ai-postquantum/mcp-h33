//! BotShield tools — free CAPTCHA replacement using SHA-256 proof-of-work.
//!
//! Two tools:
//!   - h33_botshield_challenge — issue a PoW challenge to a browser client
//!   - h33_botshield_verify    — verify a PoW solution submitted by the client
//!
//! BotShield is the no-friction CAPTCHA alternative: the customer's frontend
//! solves a small SHA-256 PoW before submitting a form. Humans don't notice
//! the ~50ms delay; bots solving thousands of requests per second get
//! rate-limited by the computational cost. No tracking, no annoying images,
//! no third-party JS. Every challenge/verify pair is substrate-anchored.

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{schema_integer, schema_string, ToolInputSchema};
use crate::token::Capability;
use serde_json::Value;
use std::sync::Arc;

pub fn challenge() -> RegisteredTool {
    RegisteredTool {
        name: "h33_botshield_challenge".into(),
        description: "Issue a BotShield SHA-256 proof-of-work challenge for a browser \
                      client. Returns a challenge token the client must solve and \
                      submit back via h33_botshield_verify. Difficulty is tunable \
                      (default ~50ms of client work). No user tracking, no third-party \
                      JS, no annoying images. Use this to gate forms, signups, or any \
                      public endpoint that attracts bot traffic."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "client_context",
                schema_string(
                    "Optional client-supplied context (e.g. form ID, IP, fingerprint) \
                     included in the challenge for binding",
                ),
            )
            .property(
                "difficulty",
                schema_integer(
                    "PoW difficulty in leading zero bits (default 18 ~= 50ms client work)",
                    Some(18),
                ),
            ),
        capability: Capability::BotshieldChallenge,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.botshield_challenge(args).await })
        }),
    }
}

pub fn verify() -> RegisteredTool {
    RegisteredTool {
        name: "h33_botshield_verify".into(),
        description: "Verify a BotShield PoW solution submitted by the browser client. \
                      Returns valid/invalid plus a substrate anchor for the \
                      challenge-response pair. Write-semantics (creates a new \
                      verification record); bypasses CacheeFlu."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "challenge_token",
                schema_string("The challenge token previously issued to the client"),
            )
            .property(
                "solution",
                schema_string("The PoW solution (nonce) the client computed"),
            )
            .require("challenge_token")
            .require("solution"),
        capability: Capability::BotshieldVerify,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.botshield_verify(args).await })
        }),
    }
}
