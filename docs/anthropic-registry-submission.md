# Anthropic / modelcontextprotocol Registry Submission

This document is the canonical, copy-paste-ready submission package for adding
`h33-mcp` to the official Model Context Protocol ecosystem maintained by
Anthropic at <https://github.com/modelcontextprotocol>.

There are **two upstream targets**, and we should land both:

| # | Repo | Purpose | Submission shape |
|---|------|---------|------------------|
| 1 | [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) | Curated `README.md` directory of community MCP servers | Markdown bullet PR |
| 2 | [`modelcontextprotocol/registry`](https://github.com/modelcontextprotocol/registry) | Machine-readable registry of `server.json` entries | New `server.json` file PR |

Pre-flight checklist (do these BEFORE opening either PR):

- [ ] `h33-mcp` v0.2.0 is published to crates.io (`cargo publish` from repo root)
- [ ] Repository is public at `https://github.com/H33ai-postquantum/mcp-h33`
- [ ] `README.md` Quickstart works on a clean machine
- [ ] `cargo install h33-mcp` works on a clean machine
- [ ] `install.h33.ai/mcp` one-liner works on macOS + Linux
- [ ] At least one screenshot of Claude Code calling an `h33_*` tool exists in `docs/screenshots/`
- [ ] Substrate attestation bundle for the release binary is anchored on chain (so the `verified` field is true)

---

## 1. PR to `modelcontextprotocol/servers`

### Branch name

```
add-h33-mcp
```

### PR title

```
Add h33-mcp — H33 post-quantum substrate, biometrics, ZK proofs (Rust)
```

### PR body

```markdown
## What this adds

`h33-mcp` is the canonical Model Context Protocol surface for the H33
post-quantum security platform. It is written in native Rust and exposes:

- **Substrate attestation** — anchor any AI inference, build artifact, document,
  or commitment with three independent post-quantum signature families
  (Dilithium + FALCON + SPHINCS+) into a 74-byte verifiable footprint
- **Biometric authentication** — fully-homomorphic-encrypted biometric enroll
  and verify, no plaintext biometric leaves the agent boundary
- **ZK-STARK proofs** — generate and verify zero-knowledge attestations of
  arbitrary statements
- **Triple-key signing** — Dilithium + FALCON + SPHINCS+ document signing and
  verification
- **BotShield** — post-quantum challenge / response that distinguishes humans,
  approved agents, and attackers
- **HICS** — H33 Integrated Cryptographic Scoring; agents can scan a codebase
  and receive a numeric improvement badge anchored to the substrate
- **HATS Tier 1 governance** — manifest read, audit log read, detection rule
  retrieval
- **Bitcoin UTXO quantum insurance** — attest, verify, and look up post-quantum
  protection bundles for individual Bitcoin UTXOs

### Why agents need this

When an agent calls an external API, today there is no portable way for that
agent to prove the call happened, what model produced the output, or that the
result was not tampered with downstream. `h33-mcp` gives every MCP-capable
agent a primitive for *cryptographic provenance*. The same primitive lets the
agent prove at PR review time that the patch it generated improved (rather
than degraded) the security posture of the codebase — the HICS badge.

Patent pending — 129 claims filed.

### Architectural rule

Agents hold short-lived `cka_*` capability tokens. Servers hold long-lived
`ck_live_*` API keys. The MCP server **refuses to start** if it is given a
`ck_live_*` key as its token, so a misconfigured agent cannot accidentally
exfiltrate a server credential. This is enforced in the entrypoint and
covered by tests.

### Install

```bash
cargo install h33-mcp
```

or

```bash
curl -sSL https://install.h33.ai/mcp | sh
```

### Configuration

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "h33": {
      "command": "h33-mcp",
      "env": { "H33_AGENT_TOKEN": "cka_..." }
    }
  }
}
```

`cka_*` tokens are minted with `h33 mint` (the sister CLI, also Rust).

### Tests

23 tools registered. 37 tests pass under `cargo test`. Round-trip integration
tests against the H33 staging environment pass. No `unsafe` code; `unwrap()`
and `expect()` are denied at the crate level.

### Maintainer

H33.ai, Inc. — <support@h33.ai>
Repository: <https://github.com/H33ai-postquantum/mcp-h33>
Crate: <https://crates.io/crates/h33-mcp>
Docs: <https://h33.ai/docs/mcp>
```

### README.md diff (third-party servers section)

The `modelcontextprotocol/servers` README has a `### 🤝 Third-Party Servers`
list. We add a single bullet, kept alphabetical:

```diff
+- **[h33-mcp](https://github.com/H33ai-postquantum/mcp-h33)** — Post-quantum substrate, FHE biometric auth, ZK-STARK proofs, triple-key signing, BotShield, HICS cryptographic scoring, HATS Tier 1 governance, Bitcoin UTXO quantum insurance. Native Rust. (`cargo install h33-mcp`)
```

If the third-party section is alphabetised by emoji-prefixed category, the
correct subsection is **🔒 Security**.

---

## 2. PR to `modelcontextprotocol/registry`

The registry expects a `server.json` file under
`servers/<namespace>/<name>/server.json`. We submit at:

```
servers/h33ai/h33-mcp/server.json
```

### server.json (drop this file in the PR)

```json
{
  "$schema": "https://modelcontextprotocol.io/schemas/registry/server.schema.json",
  "name": "h33-mcp",
  "namespace": "h33ai",
  "display_name": "H33",
  "description": "H33 post-quantum substrate, FHE biometric auth, ZK-STARK proofs, triple-key signing, BotShield, HICS cryptographic scoring, HATS Tier 1 governance, and Bitcoin UTXO quantum insurance — exposed as MCP tools for AI coding agents.",
  "homepage": "https://mcp.h33.ai",
  "repository": {
    "type": "git",
    "url": "https://github.com/H33ai-postquantum/mcp-h33"
  },
  "license": "Proprietary",
  "author": {
    "name": "H33.ai, Inc.",
    "email": "support@h33.ai",
    "url": "https://h33.ai"
  },
  "categories": [
    "security",
    "cryptography",
    "post-quantum",
    "authentication",
    "compliance"
  ],
  "tags": [
    "post-quantum",
    "dilithium",
    "falcon",
    "sphincs",
    "fhe",
    "biometrics",
    "zk-stark",
    "substrate",
    "bitcoin",
    "utxo",
    "hics",
    "hats",
    "rust"
  ],
  "runtime": {
    "language": "rust",
    "binary": "h33-mcp",
    "transports": ["stdio"]
  },
  "install": {
    "cargo": "cargo install h33-mcp",
    "homebrew": "brew install h33ai/tap/h33-mcp",
    "script": "curl -sSL https://install.h33.ai/mcp | sh"
  },
  "configuration": {
    "required_env": [
      {
        "name": "H33_AGENT_TOKEN",
        "description": "Short-lived cka_* agent capability token. Mint via `h33 mint`. NEVER pass a ck_live_* server key here — the server will refuse to start.",
        "secret": true
      }
    ],
    "optional_env": [
      {
        "name": "H33_API_BASE",
        "description": "Override the H33 API endpoint. Defaults to https://api.h33.ai.",
        "default": "https://api.h33.ai"
      }
    ]
  },
  "claude_desktop_config": {
    "mcpServers": {
      "h33": {
        "command": "h33-mcp",
        "env": { "H33_AGENT_TOKEN": "cka_..." }
      }
    }
  },
  "tools": [
    { "name": "h33_substrate_enroll",       "description": "Register a new attestation domain on the H33 substrate" },
    { "name": "h33_substrate_verify",       "description": "Verify a 74-byte substrate commitment against its on-chain anchor" },
    { "name": "h33_substrate_attest",       "description": "Attest a payload with three-family PQ signatures (Dilithium+FALCON+SPHINCS+)" },
    { "name": "h33_substrate_list_domains", "description": "List substrate domains for the calling tenant" },
    { "name": "h33_substrate_anchor_ai_inference", "description": "Anchor an AI inference (model id + prompt hash + output hash) to the substrate" },
    { "name": "h33_tenant_read",            "description": "Read the calling tenant's profile" },
    { "name": "h33_tenant_read_usage",      "description": "Read the calling tenant's usage / quota" },
    { "name": "h33_audit_read",             "description": "Read recent audit log entries for the calling tenant" },
    { "name": "h33_meta_detection_rules",   "description": "Fetch the latest H33 detection rules (YAML)" },
    { "name": "h33_meta_get_manifest",      "description": "Fetch the H33 agent manifest" },
    { "name": "h33_hics_scan",              "description": "Run an HICS scan on a codebase and return a numeric improvement score" },
    { "name": "h33_hics_badge",             "description": "Generate the substrate-anchored HICS badge for a PR or release" },
    { "name": "h33_biometric_enroll",       "description": "Enroll a biometric template under fully-homomorphic encryption" },
    { "name": "h33_biometric_verify",       "description": "Verify a probe biometric against an FHE-encrypted template" },
    { "name": "h33_zk_prove",               "description": "Generate a ZK-STARK proof for a statement" },
    { "name": "h33_zk_verify",              "description": "Verify a ZK-STARK proof" },
    { "name": "h33_triple_key_sign",        "description": "Sign a document with Dilithium + FALCON + SPHINCS+" },
    { "name": "h33_triple_key_verify",      "description": "Verify a triple-key signature" },
    { "name": "h33_botshield_challenge",    "description": "Issue a BotShield post-quantum challenge" },
    { "name": "h33_botshield_verify",       "description": "Verify a BotShield response" },
    { "name": "h33_bitcoin_attest",         "description": "Attest a Bitcoin UTXO with three-family PQ sigs and anchor a 74-byte commitment for OP_RETURN" },
    { "name": "h33_bitcoin_verify",         "description": "Verify a previously-issued Bitcoin UTXO attestation (public endpoint, no auth)" },
    { "name": "h33_bitcoin_lookup",         "description": "Look up any H33 attestations for a given UTXO (public endpoint, no auth)" }
  ],
  "verification": {
    "substrate_anchored": true,
    "patent_pending_claims": 129,
    "license_required_for_production": true
  }
}
```

### PR title

```
Add servers/h33ai/h33-mcp
```

### PR body (registry repo)

```markdown
## Adds

A `server.json` for `h33-mcp`, the canonical Model Context Protocol surface
for the H33 post-quantum security platform. 23 tools across substrate
attestation, FHE biometric auth, ZK-STARK proofs, triple-key signing,
BotShield, HICS cryptographic scoring, HATS governance, and Bitcoin UTXO
quantum insurance.

- Crate: https://crates.io/crates/h33-mcp
- Source: https://github.com/H33ai-postquantum/mcp-h33
- Docs: https://h33.ai/docs/mcp

The server is native Rust, has no `unsafe` code, denies `unwrap()` at the
crate level, refuses to start if handed a server-side `ck_live_*` API key by
mistake, and uses short-lived `cka_*` agent capability tokens for all
authenticated calls.

Maintainer: H33.ai, Inc. <support@h33.ai>
```

---

## 3. After both PRs merge

- [ ] Add the registry badge to `mcp-h33/README.md` once the canonical URL is live
- [ ] Announce on `h33.ai/blog/`, the H33 LinkedIn, and the Anthropic MCP Discord `#showcase`
- [ ] Update `h33.ai/.well-known/h33-agent-manifest.json` with the registry URL under `discovery`
- [ ] Update `h33.ai/llms.txt` with a one-line "Available on the official MCP registry" pointer
- [ ] Tag the release in this repo: `git tag h33-mcp-registry-listed-2026-04-10`

---

## Notes for the human submitting the PRs

- Open the `servers` PR **first** — it is the higher-traffic discovery surface
  and the registry repo maintainers sometimes ask for the README listing as
  proof of community uptake.
- Keep the third-party README bullet to ONE line. The `servers` repo
  maintainers reject multi-line bullets.
- Do not advertise the proprietary license in the bullet itself. Mention it
  in the PR body and let the link click through to the README handle the
  rest. The list is meant to be ecosystem-friendly.
- If a maintainer asks "is this a hosted SaaS or self-hosted?" the answer is
  "self-hosted Rust binary that talks to the hosted H33 API. The MCP server
  itself runs in the user's process and ships zero telemetry."
- If a maintainer asks about the patent status, the answer is "patent pending,
  129 claims, but the MCP server source is open-readable for audit and
  research; commercial production use requires a license per the README."
