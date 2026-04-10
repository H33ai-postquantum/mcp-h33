//! CacheeFlu — in-process two-tier tool result cache.
//!
//! Patent Claim 126: in-process ZK proof verification result cache with
//! SHA3-256-indexed keys, two-tier W-TinyLFU-inspired admission, and
//! sub-microsecond lookups. Distinct from the external high-speed
//! verification cache (Cachee) which serves external verifiers.
//!
//! Architecture:
//!
//! ```text
//!   ┌──────────────────────────┐
//!   │  Window tier (LRU)       │  small, recent additions
//!   │  size = 32               │
//!   └────────────┬─────────────┘
//!                │ promote on frequency >= 2
//!                ▼
//!   ┌──────────────────────────┐
//!   │  Main tier (LFU)         │  larger, frequency-admitted
//!   │  size = 256              │
//!   └──────────────────────────┘
//! ```
//!
//! Admission to the main tier requires the candidate's frequency counter
//! to exceed the victim's frequency. This prevents one-shot probe calls
//! from evicting hot read results.
//!
//! Read-only tools are cached. Write tools (substrate enroll, attest,
//! anchor_ai_inference, hics_scan) BYPASS the cache entirely — we never
//! cache stateful operations.

use dashmap::DashMap;
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const WINDOW_TIER_SIZE: usize = 32;
const MAIN_TIER_SIZE: usize = 256;

/// Per-tool TTL policy. Returns None for tools that bypass cache entirely.
fn ttl_for_tool(tool: &str) -> Option<Duration> {
    match tool {
        "h33_substrate_list_domains" => Some(Duration::from_secs(15 * 60)),
        "h33_substrate_verify" => Some(Duration::from_secs(30)),
        "h33_tenant_read" => Some(Duration::from_secs(60)),
        "h33_tenant_read_usage" => Some(Duration::from_secs(15)),
        "h33_audit_read" => Some(Duration::from_secs(5)),
        "h33_detection_rules" => Some(Duration::from_secs(30 * 60)),
        "h33_get_manifest" => Some(Duration::from_secs(30 * 60)),
        "h33_zk_verify" => Some(Duration::from_secs(60)),
        "h33_triple_key_verify" => Some(Duration::from_secs(60)),
        "h33_botshield_challenge" => Some(Duration::from_secs(30)),
        // Bitcoin public verification endpoints — attestations are permanent
        // so cache aggressively (5 min for verify, 10 min for lookup)
        "h33_bitcoin_verify" => Some(Duration::from_secs(5 * 60)),
        "h33_bitcoin_lookup" => Some(Duration::from_secs(10 * 60)),
        // Write tools — never cached
        _ => None,
    }
}

/// Tools that mutate state and bypass the cache entirely.
pub fn is_write_tool(tool: &str) -> bool {
    matches!(
        tool,
        "h33_substrate_enroll"
            | "h33_substrate_attest"
            | "h33_substrate_anchor_ai_inference"
            | "h33_substrate_revoke"
            | "h33_hics_scan"
            | "h33_biometric_enroll"
            | "h33_biometric_verify"
            | "h33_zk_prove"
            | "h33_triple_key_sign"
            | "h33_botshield_verify"
            // Bitcoin attest creates permanent Arweave state; verify/lookup
            // are public read-only endpoints and are cacheable
            | "h33_bitcoin_attest"
    )
}

#[derive(Debug, Clone)]
struct Entry {
    value: Value,
    cached_at: Instant,
    ttl: Duration,
    frequency: u32,
}

impl Entry {
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at) > self.ttl
    }
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub window_size: usize,
    pub main_size: usize,
    pub hits: u64,
    pub misses: u64,
    pub admissions: u64,
    pub evictions: u64,
    pub bypass_count: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// CacheeFlu — in-process two-tier tool result cache.
#[derive(Debug)]
pub struct CacheeFlu {
    window: DashMap<String, Entry>,
    main: DashMap<String, Entry>,
    hits: AtomicU64,
    misses: AtomicU64,
    admissions: AtomicU64,
    evictions: AtomicU64,
    bypass_count: AtomicU64,
}

impl CacheeFlu {
    pub fn new() -> Self {
        Self {
            window: DashMap::with_capacity(WINDOW_TIER_SIZE * 2),
            main: DashMap::with_capacity(MAIN_TIER_SIZE * 2),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            admissions: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            bypass_count: AtomicU64::new(0),
        }
    }

    /// Probe the cache for a tool result. Returns Some on hit, None on miss
    /// or for write tools (which bypass).
    pub fn get(&self, tool: &str, args: &Value) -> Option<Value> {
        if is_write_tool(tool) {
            self.bypass_count.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let key = cache_key(tool, args);
        let now = Instant::now();

        // Check main tier first
        if let Some(mut entry) = self.main.get_mut(&key) {
            if entry.is_expired(now) {
                drop(entry);
                self.main.remove(&key);
            } else {
                entry.frequency = entry.frequency.saturating_add(1);
                let value = entry.value.clone();
                drop(entry);
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(value);
            }
        }

        // Check window tier
        if let Some(mut entry) = self.window.get_mut(&key) {
            if entry.is_expired(now) {
                drop(entry);
                self.window.remove(&key);
            } else {
                entry.frequency = entry.frequency.saturating_add(1);
                let frequency = entry.frequency;
                let value = entry.value.clone();
                let entry_clone = entry.clone();
                drop(entry);

                // Promote to main tier if frequency threshold met
                if frequency >= 2 {
                    self.maybe_promote(key.clone(), entry_clone);
                }

                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(value);
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a tool result into the cache. Write tools and tools without
    /// a defined TTL are no-ops.
    pub fn set(&self, tool: &str, args: &Value, value: Value) {
        if is_write_tool(tool) {
            self.bypass_count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(ttl) = ttl_for_tool(tool) else {
            return;
        };

        let key = cache_key(tool, args);
        let entry = Entry {
            value,
            cached_at: Instant::now(),
            ttl,
            frequency: 0,
        };

        // New insertions go to the window tier first
        if self.window.len() >= WINDOW_TIER_SIZE {
            self.evict_lru_window();
        }
        self.window.insert(key, entry);
    }

    /// Promote an entry from window to main tier if frequency exceeds the
    /// main tier's least-frequent victim. This is the W-TinyLFU admission
    /// policy adapted for MCP workloads.
    fn maybe_promote(&self, key: String, entry: Entry) {
        if self.main.len() < MAIN_TIER_SIZE {
            self.main.insert(key.clone(), entry);
            self.window.remove(&key);
            self.admissions.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Find the least-frequent main tier entry
        let mut victim_key: Option<String> = None;
        let mut min_freq = u32::MAX;
        for r in self.main.iter() {
            if r.frequency < min_freq {
                min_freq = r.frequency;
                victim_key = Some(r.key().clone());
            }
        }

        // Admit only if the candidate has strictly higher frequency
        if entry.frequency > min_freq {
            if let Some(vkey) = victim_key {
                self.main.remove(&vkey);
                self.main.insert(key.clone(), entry);
                self.window.remove(&key);
                self.admissions.fetch_add(1, Ordering::Relaxed);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Simple LRU eviction for the window tier — find the oldest entry by
    /// `cached_at` and remove it. DashMap doesn't preserve insertion order
    /// so we scan, which is fine at WINDOW_TIER_SIZE = 32.
    fn evict_lru_window(&self) {
        let mut oldest_key: Option<String> = None;
        let mut oldest_time: Option<Instant> = None;
        for r in self.window.iter() {
            match oldest_time {
                None => {
                    oldest_time = Some(r.cached_at);
                    oldest_key = Some(r.key().clone());
                }
                Some(t) if r.cached_at < t => {
                    oldest_time = Some(r.cached_at);
                    oldest_key = Some(r.key().clone());
                }
                _ => {}
            }
        }
        if let Some(k) = oldest_key {
            self.window.remove(&k);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Wipe both tiers. Called on session end.
    pub fn clear(&self) {
        self.window.clear();
        self.main.clear();
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            window_size: self.window.len(),
            main_size: self.main.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            admissions: self.admissions.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            bypass_count: self.bypass_count.load(Ordering::Relaxed),
        }
    }
}

impl Default for CacheeFlu {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the canonical cache key for a tool call.
/// SHA3-256 over a canonical (sorted-key) serialization of the args.
fn cache_key(tool: &str, args: &Value) -> String {
    let canonical = canonicalize(args);
    let mut hasher = Sha3_256::new();
    hasher.update(b"h33-cacheeflu/v1");
    hasher.update([0u8]);
    hasher.update(tool.as_bytes());
    hasher.update([0u8]);
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Recursive canonical-form serializer. Object keys are emitted in sorted
/// order so {a:1,b:2} and {b:2,a:1} hash to the same key.
fn canonicalize(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "\"{}\":{}",
                        k.replace('\\', "\\\\").replace('"', "\\\""),
                        canonicalize(&obj[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_key_is_canonical() {
        // Same logical args, different key order, must produce the same key
        let args1 = json!({"a": 1, "b": 2});
        let args2 = json!({"b": 2, "a": 1});
        assert_eq!(
            cache_key("h33_substrate_verify", &args1),
            cache_key("h33_substrate_verify", &args2),
        );
    }

    #[test]
    fn write_tools_bypass() {
        let cache = CacheeFlu::new();
        let args = json!({"domain": "0x16"});
        cache.set("h33_substrate_enroll", &args, json!({"id": "abc"}));
        assert!(cache.get("h33_substrate_enroll", &args).is_none());
        assert!(cache.stats().bypass_count >= 2);
    }

    #[test]
    fn read_tools_round_trip() {
        let cache = CacheeFlu::new();
        let args = json!({});
        cache.set("h33_substrate_list_domains", &args, json!({"total": 95}));
        let result = cache.get("h33_substrate_list_domains", &args);
        assert!(result.is_some());
        assert_eq!(result.expect("hit"), json!({"total": 95}));
        assert!(cache.stats().hits >= 1);
    }

    #[test]
    fn miss_on_unknown_tool() {
        let cache = CacheeFlu::new();
        let args = json!({});
        assert!(cache.get("h33_unknown_tool", &args).is_none());
        assert!(cache.stats().misses >= 1);
    }

    #[test]
    fn unknown_tool_set_is_noop() {
        let cache = CacheeFlu::new();
        let args = json!({});
        cache.set("h33_unknown_tool", &args, json!("anything"));
        assert!(cache.get("h33_unknown_tool", &args).is_none());
    }
}
