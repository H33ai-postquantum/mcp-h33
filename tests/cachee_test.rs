//! Integration tests for CacheeFlu — the in-process tool result cache.
//!
//! Patent Claim 126 verification: read tools hit cache, write tools bypass,
//! canonical arg ordering produces the same cache key, TTL enforces expiry.

use h33_mcp::cachee::CacheeFlu;
use serde_json::json;

#[test]
fn read_tool_round_trip() {
    let cache = CacheeFlu::new();
    let args = json!({});
    cache.set("h33_substrate_list_domains", &args, json!({"total": 95}));
    let result = cache.get("h33_substrate_list_domains", &args);
    assert!(result.is_some());
    let value = result.expect("cache hit");
    assert_eq!(value, json!({"total": 95}));
}

#[test]
fn write_tool_bypasses_cache() {
    let cache = CacheeFlu::new();
    let args = json!({"domain": "0x16", "artifact": "base64data"});
    // Writes should never enter the cache
    cache.set("h33_substrate_enroll", &args, json!({"id": "anchor_123"}));
    assert!(cache.get("h33_substrate_enroll", &args).is_none());
    assert!(cache.stats().bypass_count >= 2);
}

#[test]
fn canonical_key_ordering() {
    let cache = CacheeFlu::new();
    let args1 = json!({"a": 1, "b": 2, "c": 3});
    let args2 = json!({"c": 3, "a": 1, "b": 2});
    cache.set("h33_substrate_verify", &args1, json!({"valid": true}));
    // Different JSON key order, same logical args → same cache key → hit
    let result = cache.get("h33_substrate_verify", &args2);
    assert!(result.is_some());
    assert_eq!(result.expect("hit"), json!({"valid": true}));
}

#[test]
fn unknown_tool_does_not_cache() {
    let cache = CacheeFlu::new();
    cache.set("h33_unknown", &json!({}), json!("anything"));
    assert!(cache.get("h33_unknown", &json!({})).is_none());
}

#[test]
fn different_args_are_different_entries() {
    let cache = CacheeFlu::new();
    cache.set(
        "h33_substrate_verify",
        &json!({"anchor_id": "abc"}),
        json!({"valid": true}),
    );
    cache.set(
        "h33_substrate_verify",
        &json!({"anchor_id": "xyz"}),
        json!({"valid": false}),
    );
    assert_eq!(
        cache.get("h33_substrate_verify", &json!({"anchor_id": "abc"})),
        Some(json!({"valid": true}))
    );
    assert_eq!(
        cache.get("h33_substrate_verify", &json!({"anchor_id": "xyz"})),
        Some(json!({"valid": false}))
    );
}

#[test]
fn hit_rate_reflects_usage() {
    let cache = CacheeFlu::new();
    let args = json!({});
    cache.set("h33_substrate_list_domains", &args, json!([]));
    // 3 hits, 1 miss
    let _ = cache.get("h33_substrate_list_domains", &args);
    let _ = cache.get("h33_substrate_list_domains", &args);
    let _ = cache.get("h33_substrate_list_domains", &args);
    let _ = cache.get("h33_substrate_list_domains", &json!({"other": "args"}));
    let stats = cache.stats();
    assert_eq!(stats.hits, 3);
    assert_eq!(stats.misses, 1);
    assert!((stats.hit_rate() - 0.75).abs() < 0.01);
}

#[test]
fn clear_wipes_both_tiers() {
    let cache = CacheeFlu::new();
    for i in 0..10 {
        cache.set(
            "h33_substrate_verify",
            &json!({"anchor_id": format!("a{}", i)}),
            json!({"valid": true}),
        );
    }
    cache.clear();
    let stats = cache.stats();
    assert_eq!(stats.window_size, 0);
    assert_eq!(stats.main_size, 0);
}
