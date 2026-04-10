//! Integration tests for the epoch-evolved nullifier cache.
//!
//! Patent Claim 129 verification: duplicates within an epoch are rejected,
//! different epochs produce unrelated nullifiers, different sessions
//! produce different nullifiers even for the same tool call ID.

use h33_mcp::fraud::NullifierCache;

#[test]
fn first_call_in_epoch_succeeds() {
    let cache = NullifierCache::new();
    let secret = NullifierCache::mint_session_secret("cka_test", "salt");
    let r = cache.check_and_record(&secret, "tool-call-1", 1_700_000_000_000);
    assert!(r.ok);
    assert_eq!(cache.size(), 1);
}

#[test]
fn duplicate_within_same_epoch_is_rejected() {
    let cache = NullifierCache::new();
    let secret = NullifierCache::mint_session_secret("cka_test", "salt");
    let first = cache.check_and_record(&secret, "call-1", 1_700_000_000_000);
    let second = cache.check_and_record(&secret, "call-1", 1_700_000_005_000);
    assert!(first.ok);
    assert!(!second.ok);
    assert_eq!(first.nullifier, second.nullifier);
    assert_eq!(first.epoch, second.epoch);
}

#[test]
fn different_epochs_produce_unrelated_nullifiers() {
    let cache = NullifierCache::new();
    let secret = NullifierCache::mint_session_secret("cka_test", "salt");
    let epoch_a = cache.check_and_record(&secret, "call-1", 1_700_000_000_000);
    // Cross an epoch boundary (default epoch is 60s)
    let epoch_b = cache.check_and_record(&secret, "call-1", 1_700_000_120_000);
    assert!(epoch_a.ok);
    assert!(epoch_b.ok);
    assert_ne!(epoch_a.nullifier, epoch_b.nullifier);
    assert_ne!(epoch_a.epoch, epoch_b.epoch);
}

#[test]
fn different_session_secrets_produce_different_nullifiers() {
    let secret_alice = NullifierCache::mint_session_secret("cka_alice", "salt");
    let secret_bob = NullifierCache::mint_session_secret("cka_bob", "salt");
    assert_ne!(secret_alice, secret_bob);

    let nullifier_alice = NullifierCache::compute(&secret_alice, "call-1", 28333);
    let nullifier_bob = NullifierCache::compute(&secret_bob, "call-1", 28333);
    assert_ne!(nullifier_alice, nullifier_bob);
}

#[test]
fn different_salts_produce_different_session_secrets() {
    let s1 = NullifierCache::mint_session_secret("cka_test", "salt-1");
    let s2 = NullifierCache::mint_session_secret("cka_test", "salt-2");
    assert_ne!(s1, s2);
}

#[test]
fn nullifier_format_is_deterministic() {
    let n1 = NullifierCache::compute("secret", "call", 42);
    let n2 = NullifierCache::compute("secret", "call", 42);
    assert_eq!(n1, n2);
    // 64 hex chars for SHA3-256 output
    assert_eq!(n1.len(), 64);
    assert!(n1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn many_unique_calls_succeed() {
    let cache = NullifierCache::new();
    let secret = NullifierCache::mint_session_secret("cka_test", "salt");
    for i in 0..100 {
        let call_id = format!("call-{}", i);
        let r = cache.check_and_record(&secret, &call_id, 1_700_000_000_000);
        assert!(r.ok, "call {} should succeed", i);
    }
    assert_eq!(cache.size(), 100);
}
