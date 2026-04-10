//! Epoch-Evolved Nullifier Cache
//!
//! Patent Claim 129 (FraudShield absorption). Each MCP tool call generates
//! a nullifier:
//!
//! ```text
//! nullifier = SHA3-256(
//!   "h33-mcp/v1/tool-call" ||
//!   session_secret           ||
//!   tool_call_id             ||
//!   epoch
//! )
//! ```
//!
//! Where `epoch = floor(now_ms / epoch_duration_ms)`.
//!
//! Properties:
//!   - No replay within epoch (duplicate nullifier rejected)
//!   - Cross-epoch unlinkability (different epochs produce unrelated nullifiers)
//!   - Forward secrecy (past nullifiers reveal nothing about future)
//!   - No server state required beyond a bounded DashMap with periodic eviction

use dashmap::DashMap;
use sha3::{Digest, Sha3_256};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

const DOMAIN_SEPARATOR: &[u8] = b"h33-mcp/v1/tool-call";
const DEFAULT_EPOCH_MS: u64 = 60_000;
const NULLIFIER_TTL_MS: u64 = DEFAULT_EPOCH_MS * 2;

#[derive(Debug)]
pub struct NullifierResult {
    pub ok: bool,
    pub nullifier: String,
    pub epoch: u64,
}

#[derive(Debug)]
pub struct NullifierCache {
    entries: DashMap<String, i64>,
    epoch_ms: u64,
    last_eviction: AtomicI64,
}

impl NullifierCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::with_capacity(1024),
            epoch_ms: DEFAULT_EPOCH_MS,
            last_eviction: AtomicI64::new(0),
        }
    }

    pub fn with_epoch(epoch: Duration) -> Self {
        Self {
            entries: DashMap::with_capacity(1024),
            epoch_ms: epoch.as_millis() as u64,
            last_eviction: AtomicI64::new(0),
        }
    }

    /// Compute the canonical nullifier for a tool call. Pure function.
    pub fn compute(session_secret: &str, tool_call_id: &str, epoch: u64) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(DOMAIN_SEPARATOR);
        hasher.update([0u8]);
        hasher.update(session_secret.as_bytes());
        hasher.update([0u8]);
        hasher.update(tool_call_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(epoch.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Derive a session secret from a cka_* token and a server-local salt.
    /// One-way: given the secret you cannot reconstruct the token.
    pub fn mint_session_secret(agent_token: &str, local_salt: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(b"h33-mcp/v1/session-secret");
        hasher.update([0u8]);
        hasher.update(local_salt.as_bytes());
        hasher.update([0u8]);
        hasher.update(agent_token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Check whether this nullifier has been seen in the current epoch.
    /// If not, record it and return ok=true. If seen, return ok=false.
    pub fn check_and_record(
        &self,
        session_secret: &str,
        tool_call_id: &str,
        now_ms: i64,
    ) -> NullifierResult {
        // Periodic eviction (~once per second)
        let last = self.last_eviction.load(Ordering::Relaxed);
        if now_ms - last > 1000 {
            self.evict_expired(now_ms);
            self.last_eviction.store(now_ms, Ordering::Relaxed);
        }

        let epoch = (now_ms.max(0) as u64) / self.epoch_ms;
        let nullifier = Self::compute(session_secret, tool_call_id, epoch);

        // Atomic check-and-insert
        match self.entries.entry(nullifier.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => NullifierResult {
                ok: false,
                nullifier,
                epoch,
            },
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(now_ms);
                NullifierResult {
                    ok: true,
                    nullifier,
                    epoch,
                }
            }
        }
    }

    fn evict_expired(&self, now_ms: i64) {
        let cutoff = now_ms - NULLIFIER_TTL_MS as i64;
        self.entries.retain(|_, seen_at| *seen_at >= cutoff);
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }
}

impl Default for NullifierCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_succeeds() {
        let cache = NullifierCache::new();
        let secret = NullifierCache::mint_session_secret("cka_test", "salt");
        let r = cache.check_and_record(&secret, "call-1", 1_000_000);
        assert!(r.ok);
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn duplicate_within_epoch_rejected() {
        let cache = NullifierCache::new();
        let secret = NullifierCache::mint_session_secret("cka_test", "salt");
        let r1 = cache.check_and_record(&secret, "call-1", 1_000_000);
        let r2 = cache.check_and_record(&secret, "call-1", 1_005_000);
        assert!(r1.ok);
        assert!(!r2.ok);
        assert_eq!(r1.nullifier, r2.nullifier);
    }

    #[test]
    fn different_epochs_produce_different_nullifiers() {
        let cache = NullifierCache::new();
        let secret = NullifierCache::mint_session_secret("cka_test", "salt");
        let r1 = cache.check_and_record(&secret, "call-1", 1_000_000);
        let r2 = cache.check_and_record(&secret, "call-1", 1_000_000 + 120_000);
        assert!(r1.ok);
        assert!(r2.ok);
        assert_ne!(r1.nullifier, r2.nullifier);
        assert_ne!(r1.epoch, r2.epoch);
    }

    #[test]
    fn different_session_secrets_produce_different_nullifiers() {
        let s1 = NullifierCache::mint_session_secret("cka_alice", "salt");
        let s2 = NullifierCache::mint_session_secret("cka_bob", "salt");
        let n1 = NullifierCache::compute(&s1, "call-1", 17);
        let n2 = NullifierCache::compute(&s2, "call-1", 17);
        assert_ne!(n1, n2);
    }
}
