//! Bitcoin UTXO quantum insurance tools.
//!
//! Three tools:
//!   - `h33_bitcoin_attest`  — attest a specific UTXO with three-family
//!     post-quantum signatures, writing the bundle to Arweave and a 74-byte
//!     commitment to Bitcoin itself
//!   - `h33_bitcoin_verify`  — verify a previously-issued attestation
//!     (public endpoint — no auth required)
//!   - `h33_bitcoin_lookup`  — find any H33 attestations for a given UTXO
//!     (public endpoint — no auth required)
//!
//! The Bitcoin UTXO track is a separate customer profile from application
//! developers: Bitcoin holders submit UTXOs one-at-a-time to receive a
//! permanent attestation bundle they can verify against their public keys
//! after Q-day. No SDK integration required.

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{schema_object, schema_string, ToolInputSchema};
use crate::token::Capability;
use serde_json::Value;
use std::sync::Arc;

pub fn attest() -> RegisteredTool {
    RegisteredTool {
        name: "h33_bitcoin_attest".into(),
        description: "Attest a specific Bitcoin UTXO with three independent post-quantum \
                      signatures (Dilithium + FALCON + SPHINCS+). The full ~33 KB signature \
                      bundle is written permanently to Arweave. A 32-byte SHA3-256 commitment \
                      plus 42-byte retrieval pointer (74 bytes total) is returned for embedding \
                      in a Bitcoin OP_RETURN transaction output. When quantum computing breaks \
                      classical ECDSA, the UTXO holder can still prove ownership using the \
                      three-family post-quantum attestation. Requires proof of control via a \
                      signed message using the private key holding the UTXO. Patent Extension \
                      12 — tokenized real-world asset compliance applied to Bitcoin UTXOs."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "utxo",
                schema_string("The UTXO in txid:vout format (e.g., 'abc123...:0')"),
            )
            .property(
                "owner_address",
                schema_string(
                    "The Bitcoin address currently holding the UTXO (e.g., bc1q... or 1..., 3...)",
                ),
            )
            .property(
                "ownership_proof",
                schema_object(
                    "Signed proof of control: {message: '...', signature: '...'} where \
                     the signature is produced by the private key holding the UTXO using \
                     Bitcoin's message signing format (BIP 137 or equivalent)",
                ),
            )
            .property(
                "storage_tier",
                schema_string(
                    "'arweave_permanent' (default, recommended), 'cachee_standard', or \
                     'cachee_premium'. Arweave is the only tier that survives H33 itself.",
                ),
            )
            .require("utxo")
            .require("owner_address")
            .require("ownership_proof"),
        capability: Capability::BitcoinAttest,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.bitcoin_attest(args).await })
        }),
    }
}

pub fn verify() -> RegisteredTool {
    RegisteredTool {
        name: "h33_bitcoin_verify".into(),
        description: "Verify a previously-issued Bitcoin UTXO attestation by attestation ID. \
                      Read-only. PUBLIC endpoint — no authentication required, so any party \
                      can verify an attestation without an H33 account. Fetches the bundle \
                      from Arweave, recomputes the 32-byte SHA3-256 commitment from the \
                      three-family signatures, confirms it matches the on-chain commitment, \
                      and verifies each of the three signatures against the claimed owner's \
                      public key. Returns a verification result with all intermediate values."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "attestation_id",
                schema_string(
                    "The attestation ID returned by h33_bitcoin_attest, e.g., 'h33-btc-att-<uuid>'",
                ),
            )
            .require("attestation_id"),
        capability: Capability::BitcoinVerify,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move {
                let id = args
                    .get("attestation_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::Error::InvalidArgument(
                            "h33_bitcoin_verify requires 'attestation_id'".into(),
                        )
                    })?;
                ctx.api.bitcoin_verify(id).await
            })
        }),
    }
}

pub fn lookup() -> RegisteredTool {
    RegisteredTool {
        name: "h33_bitcoin_lookup".into(),
        description: "Find any H33 attestations issued for a given Bitcoin UTXO. Read-only. \
                      PUBLIC endpoint — no authentication required. Useful for: (a) a Bitcoin \
                      holder checking if someone else has already attested their UTXO (they \
                      shouldn't be able to without the signed ownership proof); (b) a quantum \
                      insurance auditor finding all attestations for a specific address; (c) a \
                      buyer of a Bitcoin UTXO verifying it came with a quantum insurance \
                      attestation. Returns attestation IDs, on-chain commitments, and Arweave \
                      TxIDs for every attestation touching this UTXO."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "utxo",
                schema_string("The UTXO in txid:vout format (e.g., 'abc123...:0')"),
            )
            .require("utxo"),
        capability: Capability::BitcoinLookup,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move {
                let utxo = args
                    .get("utxo")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::Error::InvalidArgument(
                            "h33_bitcoin_lookup requires 'utxo' in 'txid:vout' format".into(),
                        )
                    })?;
                ctx.api.bitcoin_lookup(utxo).await
            })
        }),
    }
}
