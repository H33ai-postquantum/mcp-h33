# h33-mcp

**H33 Model Context Protocol server — native Rust.**

The canonical MCP surface for H33 post-quantum security infrastructure. Connects Claude Code, Cursor, Codex, Aider, and any MCP-capable AI coding agent directly to the H33 substrate primitive, biometric authentication, ZK-STARK proofs, triple-key signing, BotShield, HICS cryptographic scoring, and HATS governance.

```
┌──────────────────────────────┐
│  Claude Code  ─┐             │
│  Cursor       ─┤             │
│  Codex        ─┼──►  h33-mcp │  ← native Rust, this crate
│  Aider        ─┘             │
│                              │
│  stdio JSON-RPC 2.0          │
└──────────────┬───────────────┘
               │
               │  HTTPS + cka_*
               ▼
┌──────────────────────────────┐
│  H33 Backend (Rust, Graviton4)│
│  scif-backend                │
│  auth1-delivery-rs           │
└──────────────────────────────┘
```

---

## The architectural rule

> **Agents hold `cka_*`. Servers hold `ck_live_*`. They are never the same thing.**

`ck_live_*` production keys are server-side credentials. They never enter an agent context. `cka_*` agent capability tokens are short-lived, scoped, attributable, and what every AI agent uses to call H33. The MCP server refuses to start if it is given a `ck_live_*` key as its token.

See [`docs/agent-token-architecture.md`](https://h33.ai/docs/agent-token-architecture) in the H33 docs site for the full token format spec.

---

## Install

### Via cargo

```bash
cargo install h33-mcp
```

### Via Homebrew (macOS / Linux)

```bash
brew tap h33ai/tap
brew install h33-mcp
```

### Via one-command installer

```bash
curl -sSL https://install.h33.ai/mcp | sh
```

The installer detects your platform, downloads the signed release binary from GitHub, verifies its substrate anchor, and places it on your `PATH`.

---

## Quickstart

```bash
# 1. Mint a cka_* agent token (from the h33 CLI)
h33 mint
# → export H33_AGENT_TOKEN=cka_AQAA...

# 2. Run the MCP server
h33-mcp

# Or configure your terminal AI to launch it:
#   Claude Code:  see ~/.claude/mcp.json below
#   Cursor:       see .cursor/mcp.json below
```

### Claude Code configuration

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "h33": {
      "command": "h33-mcp",
      "env": {
        "H33_AGENT_TOKEN": "cka_...",
        "H33_API_BASE": "https://sandbox.api.h33.ai"
      }
    }
  }
}
```

### Cursor configuration

Add to `.cursor/mcp.json`:

```json
{
  "mcp": {
    "servers": {
      "h33": {
        "command": "h33-mcp",
        "env": {
          "H33_AGENT_TOKEN": "cka_...",
          "H33_API_BASE": "https://sandbox.api.h33.ai"
        }
      }
    }
  }
}
```

---

## Tools exposed

**20 tools** covering the full H33 product surface plus the platform plumbing every agent needs.

### Substrate primitive (5)
| Tool | Capability | Purpose |
|---|---|---|
| `h33_substrate_enroll` | `substrate:enroll` | Create a new 74-byte substrate anchor |
| `h33_substrate_verify` | `substrate:verify` | Verify an existing anchor |
| `h33_substrate_attest` | `substrate:attest` | Issue a fresh attestation |
| `h33_substrate_list_domains` | `substrate:list_domains` | List all 95 registry domain identifiers |
| `h33_substrate_anchor_ai_inference` | `substrate:anchor_ai_inference` | Substrate + HATS Tier 1 in one call |

### Biometric authentication (2) — H33-128
| Tool | Capability | Purpose |
|---|---|---|
| `h33_biometric_enroll` | `biometric:enroll` | Enroll a user template under FHE |
| `h33_biometric_verify` | `biometric:verify` | Verify a probe (~35.25 µs/auth) |

### Zero-knowledge proofs (2) — STARK lookup
| Tool | Capability | Purpose |
|---|---|---|
| `h33_zk_prove` | `zk:prove` | Generate a 192-byte STARK proof |
| `h33_zk_verify` | `zk:verify` | Verify a STARK proof (~0.2 µs) |

### Triple-key signing (2) — Bitcoin OP_RETURN fit
| Tool | Capability | Purpose |
|---|---|---|
| `h33_triple_key_sign` | `triple_key:sign` | Ed25519 + Dilithium-5 + FALCON-512 nested |
| `h33_triple_key_verify` | `triple_key:verify` | Verify a 74-byte triple-key anchor |

### BotShield (2) — free CAPTCHA alternative
| Tool | Capability | Purpose |
|---|---|---|
| `h33_botshield_challenge` | `botshield:challenge` | Issue a SHA-256 PoW challenge |
| `h33_botshield_verify` | `botshield:verify` | Verify a PoW solution |

### HICS cryptographic scoring (2)
| Tool | Capability | Purpose |
|---|---|---|
| `h33_hics_scan` | `hics:scan` | STARK-proven code security score (before/after delta) |
| `h33_hics_badge` | `hics:badge` | Format a scan result as a Markdown PR badge |

### Platform (4)
| Tool | Capability | Purpose |
|---|---|---|
| `h33_tenant_read` | `tenant:read` | Tenant metadata |
| `h33_tenant_read_usage` | `tenant:read_usage` | Quota and usage |
| `h33_audit_read` | `audit:read` | Agent session audit log |
| `h33_detection_rules` | `mcp:connect` | Fetch classical-crypto detection rules YAML |
| `h33_get_manifest` | `mcp:connect` | Fetch the agent capability manifest |

---

## Fraud protection — the MCP eating its own dog food

Every tool call flows through a fraud guard that applies H33's own FraudShield primitives to the MCP surface. Six layered defenses:

1. **Epoch-evolved nullifier** (Patent Claim 129)
   `SHA3-256(domain || session_secret || call_id || epoch)` prevents replay within an epoch and makes cross-epoch correlation impossible.

2. **Behavioral anomaly detection** (Patent Claim 128)
   Baseline over first 20 calls, then flag call-rate spikes, write-ratio shifts, error rate jumps, tool diversity explosions, and burstiness anomalies.

3. **Binary output minimization** (Patent Claim 127)
   Auth-boundary errors return only `{"error": "auth_failed"}` — no session IDs, no capability metadata, no timing oracles.

4. **Dynamic risk scoring**
   Each suspicious event adds to a per-session risk score. Above 0.3 → shadow mode (writes become dry-run). Above 0.6 → read-only. Above 0.85 → immediate revocation.

5. **Substrate-anchored session transcript** (Patent Extension 22)
   Every 60 seconds, session activity is committed to an `AUDIT_ENTRY` (0x59) substrate anchor chained to the prior anchor. On session end, an `AUDIT_SEAL` (0x5A) commits the full chain. Tamper-evident forensic evidence.

6. **Customer webhook alert pipeline**
   Anomalies, mode changes, and revocations fire HMAC-SHA3-256-signed webhooks to the customer's security team endpoint with exponential backoff retry and dead-letter queue.

Plus HATS Tier 1 self-registration: the MCP server is itself an AI-facing endpoint, so it registers itself in HATS governance at startup and attaches the proof ID to every response.

See [`docs/mcp-fraud-protection.md`](https://h33.ai/docs/mcp-fraud-protection) in the H33 docs site for the full design.

---

## CacheeFlu — in-process tool result cache

Patent Claim 126. Read-only tool calls are absorbed by an in-process two-tier W-TinyLFU-inspired cache:

- **Window tier** (32 entries, LRU) — recent additions
- **Main tier** (256 entries, LFU) — frequency-admitted from the window

SHA3-256 keyed. Sub-microsecond lookups. Write tools (`enroll`, `attest`, `anchor_ai_inference`, `hics_scan`, etc.) bypass the cache entirely. Per-tool TTL policy tuned for MCP workloads (registry list: 15 min, tenant metadata: 60 s, audit log: 5 s).

Distinct from the external high-speed verification cache (Cachee) in `scif-backend` which stores full PQ signature sets for external verifiers.

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `H33_AGENT_TOKEN` | yes | `cka_*` agent capability token — NEVER a `ck_live_*` key |
| `H33_API_BASE` | no | H33 API base URL (default: `https://sandbox.api.h33.ai`) |
| `H33_WEBHOOK_URL` | no | Customer webhook URL for fraud alerts |
| `H33_WEBHOOK_SECRET` | no | HMAC secret for webhook signing |
| `H33_MCP_LOCAL_SALT` | no | Local salt for nullifier session secret (fresh UUID per process by default) |
| `H33_MCP_SESSION_ID` | no | Override the server session ID (fresh UUIDv7 by default) |
| `H33_TRANSCRIPT_PERIOD_SECONDS` | no | Transcript flush period (default: 60) |
| `H33_DISABLE_TRANSCRIPT` | no | Disable Extension 22 transcript chain (default: false) |
| `H33_DISABLE_HATS` | no | Disable HATS Tier 1 self-registration (default: false) |
| `H33_LOG` | no | Log level filter (default: `info`) |

---

## Building from source

```bash
git clone https://github.com/H33ai-postquantum/mcp-h33
cd mcp-h33
cargo build --release
./target/release/h33-mcp --help
```

Release binary is ~6 MB after `lto = "fat"` + `strip = true`. Startup time ~3 ms. Resident memory ~8 MB.

### Running the tests

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

### Integration tests against sandbox

```bash
H33_AGENT_TOKEN=cka_... cargo test --test integration -- --ignored
```

---

## Architecture

```
mcp-h33/
├── src/
│   ├── main.rs                — entry point, signal handling, runtime init
│   ├── lib.rs                 — crate root, module exports
│   ├── config.rs              — CLI + env var config with token validation
│   ├── error.rs               — error types with auth-boundary classification
│   ├── server.rs              — main dispatch loop, initialize/list_tools/call_tool
│   ├── protocol/
│   │   ├── jsonrpc.rs         — JSON-RPC 2.0 envelope types
│   │   ├── messages.rs        — MCP message types (Initialize, ListTools, CallTool)
│   │   └── stdio.rs           — newline-delimited stdio transport
│   ├── token/
│   │   └── cka.rs             — cka_* token format (HMAC-SHA3-256, capability bitmap)
│   ├── cachee/
│   │   └── flu.rs             — CacheeFlu two-tier W-TinyLFU cache (Patent Claim 126)
│   ├── fraud/
│   │   ├── nullifier.rs       — Epoch-evolved nullifier (Patent Claim 129)
│   │   ├── anomaly.rs         — Behavioral anomaly detection (Patent Claim 128)
│   │   ├── responses.rs       — Binary output minimization (Patent Claim 127)
│   │   ├── risk.rs            — Dynamic session risk scoring
│   │   ├── transcript.rs      — Substrate-anchored audit chain (Extension 22)
│   │   ├── alerts.rs          — Customer webhook alert pipeline
│   │   ├── hats.rs            — HATS Tier 1 self-registration
│   │   └── guard.rs           — FraudGuard composition
│   ├── client/
│   │   └── h33_api.rs         — reqwest client for scif-backend + auth1-delivery-rs
│   └── tools/
│       ├── registry.rs        — Tool registry + build_full_registry()
│       ├── substrate.rs       — 5 substrate tools
│       ├── tenant.rs          — 3 tenant/audit tools
│       ├── meta.rs            — 2 discovery tools
│       ├── hics.rs            — 2 HICS tools
│       ├── biometric.rs       — 2 biometric tools (Tier 1)
│       ├── zk.rs              — 2 ZK tools (Tier 1)
│       ├── triple_key.rs      — 2 triple-key tools (Tier 1)
│       └── botshield.rs       — 2 BotShield tools (Tier 1)
└── tests/
    ├── nullifier_test.rs      — epoch evolution, replay rejection
    ├── token_test.rs          — round-trip, tamper detection, expiry
    ├── cachee_test.rs         — two-tier admission, TTL, write bypass
    └── integration_test.rs    — end-to-end against sandbox (ignored by default)
```

---

## The integration flywheel

H33 MCP is designed around the **integrate-then-prove flywheel**: every PR an agent opens after integrating H33 substrate carries a HICS badge that cryptographically proves the integration improved the codebase's security score.

```
Agent reads  https://h33.ai/llms.txt
     ↓
Agent reads  https://h33.ai/detection-rules.yaml
     ↓
Agent runs   h33_hics_scan (BASELINE)    →  67 / 100  D
     ↓
Agent wraps  classical crypto via h33_substrate_enroll
     ↓
Agent runs   h33_hics_scan (AFTER)       →  94 / 100  A
     ↓
Agent calls  h33_hics_badge              →  Markdown badge
     ↓
Agent opens  PR with the badge
     ↓
Team sees    D → A  cryptographic improvement with STARK proof
     ↓
Team asks    "what's H33?"
     ↓
Loop
```

Every PR is a sales document. Every badge is a public proof of security improvement. See the full design in [`docs/hics-mcp-integration.md`](https://h33.ai/docs/hics-mcp-integration).

---

## The 30-second CISO pitch

> **Post-quantum security in 2 minutes. With cryptographic proof of improvement.**
>
> In the time it takes an attacker to map your crypto architecture, your terminal AI has already post-quantum-protected it AND produced a STARK-proven score showing the improvement. Two minutes. One API key. Bitcoin Core developers confirmed the architecture in April 2026.
>
> Every PR your team opens after integrating H33 carries a HICS badge that proves cryptographic improvement was real. Verifiable. Signed. Anchored. The badge is the sales document.
>
> No other post-quantum vendor offers this. ISARA, PQShield, CryptoNext sell libraries. We sell libraries plus the proof the libraries worked plus the badge that lets your team show off the proof.
>
> Patent pending — 129 claims filed.

---

## Publishing to crates.io

`h33-mcp` is published to crates.io so the Anthropic MCP registry entry and `cargo install h33-mcp` flow stay canonical.

```bash
# 1. Verify the crate builds, packages, and would upload cleanly.
cargo publish --dry-run

# 2. Bump the version in Cargo.toml (semver) and update CHANGELOG.md if present.
#    The first release that adds Bitcoin UTXO tools is v0.2.0.

# 3. Publish.
cargo publish

# 4. After publish, tag the release and push.
git tag h33-mcp-v$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
git push --tags
```

The first publish creates the crates.io listing that the Anthropic MCP registry PR
references. Subsequent publishes only require steps 2–4. Customers install with:

```bash
cargo install h33-mcp
```

The `install.h33.ai` script also drops a signed prebuilt `h33-mcp` binary on
Linux and macOS so users do not need a Rust toolchain.

---

## License

Proprietary — Commercial License Required. Commercial customers should sign up at [h33.ai/signup](https://h33.ai/signup).

This repository is open-source-readable for research, audit, and reference-implementation purposes. Redistribution, production use, and derivative works require a commercial license.

---

## Resources

- Website: [h33.ai](https://h33.ai)
- Docs: [h33.ai/docs](https://h33.ai/docs)
- OpenAPI: [api.h33.ai/openapi.json](https://api.h33.ai/openapi.json)
- Agent manifest: [h33.ai/.well-known/h33-agent-manifest.json](https://h33.ai/.well-known/h33-agent-manifest.json)
- Detection rules: [h33.ai/detection-rules.yaml](https://h33.ai/detection-rules.yaml)
- Install: [install.h33.ai](https://install.h33.ai)
- Support: support@h33.ai
- Security: security@h33.ai

---

*H33 MCP · native Rust · the canonical MCP surface for H33 post-quantum security · Patent pending · 129 claims filed*
