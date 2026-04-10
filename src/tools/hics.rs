//! HICS tools — STARK-proven cryptographic security scoring.
//!
//! Two tools:
//!   - h33_hics_scan  — run a HICS scan, optionally compared against a baseline
//!   - h33_hics_badge — format a scan result as a Markdown PR badge
//!
//! Integrate-then-prove flywheel: the agent calls scan before substrate
//! integration to capture baseline, then again after integration with
//! comparison_baseline set. The before/after delta becomes the PR badge
//! that proves the integration improved cryptographic security. Patent
//! Extension 11 (CODE_SCOPE / CODE_PROD) context.

use super::registry::{RegisteredTool, ToolContext};
use crate::protocol::messages::{
    schema_array, schema_boolean, schema_object, schema_string, ToolInputSchema,
};
use crate::token::Capability;
use crate::Result;
use serde_json::Value;
use std::sync::Arc;

pub fn scan() -> RegisteredTool {
    RegisteredTool {
        name: "h33_hics_scan".into(),
        description: "Run a HICS (H33 Integrated Cryptographic Scoring) scan against a \
                      codebase path. Returns a STARK-proven cryptographic security score \
                      in [0, 100] with a Dilithium signature, category breakdown, \
                      findings list, and a CODE_SCORE substrate anchor (domain 0x0D). \
                      RECOMMENDED WORKFLOW: call once before substrate integration to \
                      capture baseline, then again after integration with comparison_baseline \
                      set. The resulting before/after delta is the PR badge that proves \
                      the integration improved cryptographic security. Patent Claim: CODE_SCORE."
            .into(),
        input_schema: ToolInputSchema::object()
            .property("path", schema_string("Filesystem path to scan (file or directory)"))
            .property(
                "comparison_baseline",
                schema_object(
                    "Optional baseline record from a prior scan. If provided, the result \
                     includes a comparison block showing delta and grade change.",
                ),
            )
            .property(
                "categories",
                schema_array("Optional list of category names to limit the scan to", "string"),
            )
            .property(
                "include_proof",
                schema_boolean("Whether to include the STARK proof bundle", true),
            )
            .require("path"),
        capability: Capability::HicsScan,
        handler: Arc::new(|ctx: ToolContext, args: Value| {
            Box::pin(async move { ctx.api.hics_scan(args).await })
        }),
    }
}

pub fn badge() -> RegisteredTool {
    RegisteredTool {
        name: "h33_hics_badge".into(),
        description: "Format a HICS scan result as a Markdown badge ready for inclusion \
                      in a PR description. Renders the before/after score table, the \
                      proof links, and the top remaining findings. Call with the result \
                      of h33_hics_scan. Every PR an agent opens after integrating H33 \
                      substrate should include this badge as proof of improvement."
            .into(),
        input_schema: ToolInputSchema::object()
            .property(
                "scan_result",
                schema_object("The scan result object returned by h33_hics_scan"),
            )
            .require("scan_result"),
        capability: Capability::HicsBadge,
        handler: Arc::new(|_ctx: ToolContext, args: Value| {
            Box::pin(async move { format_badge(args) })
        }),
    }
}

/// Pure function — no API call. Renders a Markdown badge from a scan result.
fn format_badge(args: Value) -> Result<Value> {
    let scan = args.get("scan_result").cloned().unwrap_or(Value::Null);
    if scan.is_null() {
        return Err(crate::Error::InvalidArgument(
            "h33_hics_badge requires 'scan_result' object from h33_hics_scan".into(),
        ));
    }
    let score = scan.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let grade = scan.get("grade").and_then(|v| v.as_str()).unwrap_or("?");
    let pq_ready = scan.get("pq_ready").and_then(|v| v.as_bool()).unwrap_or(false);
    let proof = scan.get("proof").cloned().unwrap_or(Value::Null);
    let proof_id = proof
        .get("stark_proof_id")
        .and_then(|v| v.as_str())
        .unwrap_or("n/a");
    let substrate_anchor = proof
        .get("substrate_anchor")
        .and_then(|v| v.as_str())
        .unwrap_or("n/a");
    let verify_url = proof
        .get("verification_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://h33.ai/verify");

    let mut md = String::new();
    md.push_str("## HICS Cryptographic Security Score\n\n");

    if let Some(comparison) = scan.get("comparison") {
        let baseline_score = comparison
            .get("baseline_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let delta = comparison.get("delta").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let grade_change = comparison
            .get("grade_change")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        md.push_str("|        | Score        | Grade | PQ Ready |\n");
        md.push_str("|--------|--------------|-------|----------|\n");
        md.push_str(&format!(
            "| Before | {} / 100     | —     | —        |\n",
            baseline_score as i64
        ));
        md.push_str(&format!(
            "| **After**  | **{} / 100** | **{}**  | {} |\n",
            score as i64,
            grade,
            if pq_ready { "✅" } else { "❌" }
        ));
        md.push_str(&format!(
            "| **Δ**  | **+{}**       | {} | |\n\n",
            delta as i64, grade_change
        ));
    } else {
        md.push_str("| Score | Grade | PQ Ready |\n");
        md.push_str("|-------|-------|----------|\n");
        md.push_str(&format!(
            "| {} / 100 | {} | {} |\n\n",
            score as i64,
            grade,
            if pq_ready { "✅" } else { "❌" }
        ));
    }

    md.push_str(&format!(
        "**STARK proof:** `{}` · **Substrate anchor:** `{}...` · [Verify]({})\n",
        proof_id,
        substrate_anchor.chars().take(16).collect::<String>(),
        verify_url
    ));

    Ok(Value::String(md))
}
