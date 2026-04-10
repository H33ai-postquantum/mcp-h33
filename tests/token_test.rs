//! Integration tests for the cka_* agent token format.
//!
//! Verifies the 64-byte payload layout, HMAC-SHA3-256 signature, capability
//! bitmap semantics, expiry enforcement, and the prefix rules that refuse
//! ck_live_* / ck_test_* keys.

use h33_mcp::token::cka::{self, Capability, Environment, TokenError};

const TEST_SECRET: &[u8] = b"h33-mcp-integration-test-secret-do-not-use-in-production";

#[test]
fn round_trip_preserves_all_fields() {
    let token = cka::mint(
        TEST_SECRET,
        Environment::Sandbox,
        1234,
        [0xde; 16],
        1_700_000_000_000,
        3_600_000,
        &[
            Capability::SubstrateEnroll,
            Capability::SubstrateVerify,
            Capability::HicsScan,
            Capability::BiometricVerify,
            Capability::TripleKeySign,
        ],
        0,
        0,
    )
    .expect("mint should succeed");

    let parsed =
        cka::AgentToken::parse(&token, TEST_SECRET, 1_700_000_500_000).expect("parse should succeed");
    assert_eq!(parsed.tenant_id, 1234);
    assert_eq!(parsed.session_id, [0xde; 16]);
    assert_eq!(parsed.issued_at, 1_700_000_000_000);
    assert_eq!(parsed.expires_at, 1_700_003_600_000);
    assert_eq!(parsed.environment, Environment::Sandbox);
    assert!(parsed.has_capability(Capability::SubstrateEnroll));
    assert!(parsed.has_capability(Capability::SubstrateVerify));
    assert!(parsed.has_capability(Capability::HicsScan));
    assert!(parsed.has_capability(Capability::BiometricVerify));
    assert!(parsed.has_capability(Capability::TripleKeySign));
    assert!(!parsed.has_capability(Capability::TenantDelete));
    assert!(!parsed.has_capability(Capability::SubstrateRevoke));
    assert!(parsed.is_sandbox());
}

#[test]
fn expired_token_rejected() {
    let token = cka::mint(
        TEST_SECRET,
        Environment::Sandbox,
        1,
        [0u8; 16],
        1_000_000_000,
        60_000,
        &[Capability::SubstrateEnroll],
        0,
        0,
    )
    .expect("mint");
    // Now is far past expiry
    let result = cka::AgentToken::parse(&token, TEST_SECRET, 9_000_000_000);
    assert!(matches!(result, Err(TokenError::Expired(_, _))));
}

#[test]
fn wrong_secret_rejected() {
    let token = cka::mint(
        TEST_SECRET,
        Environment::Sandbox,
        1,
        [0u8; 16],
        1_700_000_000_000,
        60_000,
        &[Capability::SubstrateEnroll],
        0,
        0,
    )
    .expect("mint");
    let result = cka::AgentToken::parse(&token, b"different-secret", 1_700_000_000_000);
    assert!(matches!(result, Err(TokenError::HmacFailed)));
}

#[test]
fn tampered_token_rejected() {
    let token = cka::mint(
        TEST_SECRET,
        Environment::Sandbox,
        1,
        [0u8; 16],
        1_700_000_000_000,
        60_000,
        &[Capability::SubstrateEnroll],
        0,
        0,
    )
    .expect("mint");
    // Flip a character somewhere in the base64 body
    let mut chars: Vec<char> = token.chars().collect();
    let idx = chars.len() / 2;
    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    let result = cka::AgentToken::parse(&tampered, TEST_SECRET, 1_700_000_000_000);
    assert!(
        matches!(
            result,
            Err(TokenError::HmacFailed)
                | Err(TokenError::Base64Decode)
                | Err(TokenError::PayloadLength(_, _))
        ),
        "expected rejection, got {:?}",
        result
    );
}

#[test]
fn missing_prefix_rejected() {
    let result = cka::AgentToken::parse("ck_live_abc", TEST_SECRET, 1_700_000_000_000);
    assert!(matches!(result, Err(TokenError::MissingPrefix)));
}

#[test]
fn capability_bitmap_is_precise() {
    let token = cka::mint(
        TEST_SECRET,
        Environment::Sandbox,
        1,
        [0u8; 16],
        1_700_000_000_000,
        3_600_000,
        &[Capability::HicsScan, Capability::BotshieldVerify],
        0,
        0,
    )
    .expect("mint");
    let parsed = cka::AgentToken::parse(&token, TEST_SECRET, 1_700_000_500_000).expect("parse");
    assert!(parsed.has_capability(Capability::HicsScan));
    assert!(parsed.has_capability(Capability::BotshieldVerify));
    // These should NOT be set
    assert!(!parsed.has_capability(Capability::SubstrateEnroll));
    assert!(!parsed.has_capability(Capability::TenantRotateKeys));
    assert!(!parsed.has_capability(Capability::SubstrateRevoke));
}
