//! MCP server main loop.
//!
//! Ties together the protocol layer, the fraud guard, the CacheeFlu
//! cache, the tool registry, and the H33 API client. Runs over stdio
//! JSON-RPC and dispatches every tool call through the full fraud +
//! cache + API pipeline.

use crate::cachee::CacheeFlu;
use crate::client::H33ApiClient;
use crate::config::SharedConfig;
use crate::fraud::{
    alerts::{AlertEvent, AlertPayload, AlertPipeline, AlertPipelineConfig},
    guard::{FraudGuard, FraudGuardConfig},
    hats::{register_mcp_with_hats, HatsRegistration},
    risk::RiskEvent,
    transcript::SessionTranscript,
};
use crate::protocol::jsonrpc::{error_codes, Request, Response};
use crate::protocol::messages::{
    CallToolParams, CallToolResult, InitializeParams, InitializeResult, ListToolsResult,
    ServerCapabilities, ServerInfo, ToolContent, ToolsCapability,
};
use crate::protocol::StdioTransport;
use crate::tools::{build_full_registry, ToolContext, ToolRegistry};
use crate::{Result, SERVER_NAME, SERVER_VERSION};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Main server state shared across every request dispatch.
#[derive(Debug)]
pub struct Server {
    config: SharedConfig,
    api: Arc<H33ApiClient>,
    cachee: Arc<CacheeFlu>,
    fraud: Arc<FraudGuard>,
    tools: Arc<ToolRegistry>,
    transport: Arc<StdioTransport>,
    transcript: Option<Arc<SessionTranscript>>,
    hats: parking_lot::RwLock<Option<HatsRegistration>>,
}

impl Server {
    pub async fn new(config: SharedConfig) -> Result<Arc<Self>> {
        let api = Arc::new(H33ApiClient::new(
            config.api_base.clone(),
            config.agent_token.clone(),
        )?);
        let cachee = Arc::new(CacheeFlu::new());

        // Build the transcript (if enabled) first so the fraud guard can
        // reference it.
        let transcript = if config.disable_transcript {
            None
        } else {
            Some(SessionTranscript::new(
                config.session_id.clone(),
                Arc::clone(&api),
                Duration::from_secs(config.transcript_period_seconds),
            ))
        };

        // Alert pipeline
        let alerts = AlertPipeline::new(AlertPipelineConfig::new(
            config.webhook_url.clone(),
            config.webhook_secret.clone(),
        ));

        // Fraud guard wires all the pieces together
        let fraud = Arc::new(FraudGuard::new(FraudGuardConfig {
            agent_token: config.agent_token.clone(),
            local_salt: config.local_salt.clone(),
            transcript: transcript.clone(),
            alerts,
        }));

        // Tool registry
        let tools = Arc::new(build_full_registry());

        Ok(Arc::new(Self {
            config,
            api,
            cachee,
            fraud,
            tools,
            transport: Arc::new(StdioTransport::new()),
            transcript,
            hats: parking_lot::RwLock::new(None),
        }))
    }

    /// Register the MCP server as a HATS Tier 1 endpoint at startup.
    /// Graceful degradation — a failure does NOT block startup.
    pub async fn register_hats(self: &Arc<Self>) {
        if self.config.disable_hats {
            tracing::info!("HATS self-registration disabled by config");
            return;
        }
        match register_mcp_with_hats(
            Arc::clone(&self.api),
            &self.config.session_id,
            SERVER_VERSION,
        )
        .await
        {
            Ok(Some(reg)) => {
                tracing::info!(
                    "HATS registered · tier=1 · proof={} · anchor={}",
                    reg.proof_short(),
                    reg.anchor_short()
                );
                *self.hats.write() = Some(reg);
            }
            Ok(None) => {
                tracing::warn!("HATS layer unavailable — server continues without HATS proof");
            }
            Err(e) => {
                tracing::warn!("HATS self-registration failed: {}", e);
            }
        }
    }

    /// Start the substrate-anchored session transcript chain.
    pub fn start_transcript(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        self.transcript.as_ref().map(|t| t.spawn_periodic_flush())
    }

    /// Fire the initial session_started alert.
    pub fn fire_session_started(self: &Arc<Self>) {
        let hats = self.hats.read();
        self.fraud.alerts().fire(AlertPayload {
            event: AlertEvent::SessionStarted,
            session_id: self.config.session_id.clone(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            human_user_id: None,
            agent_identifier: None,
            risk_score: Some(0.0),
            mode: Some("normal".into()),
            reasons: None,
            substrate_anchor: hats.as_ref().map(|h| h.anchor_id.clone()),
            hats_proof: hats.as_ref().map(|h| h.proof_id.clone()),
            recommended_action: None,
            extra: Some(json!({
                "mcp_version": SERVER_VERSION,
                "api_base": self.config.api_base,
                "tool_count": self.tools.count(),
            })),
        });
    }

    /// Drive the stdio receive loop — handles initialize, tools/list, tools/call.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let me = Arc::clone(&self);
        self.transport
            .run(move |request| {
                let server = Arc::clone(&me);
                async move { handle_request(server, request).await }
            })
            .await
    }

    /// Graceful shutdown — seal the transcript chain, fire session_ended,
    /// drain alerts, clear the cache.
    pub async fn shutdown(self: &Arc<Self>) {
        tracing::info!("shutting down · sealing transcript chain");

        // Seal the transcript
        if let Some(t) = &self.transcript {
            match t.seal().await {
                Ok(Some(receipt)) => {
                    tracing::info!(
                        "transcript sealed · anchor={}... chain_length={}",
                        receipt.anchor_id.chars().take(16).collect::<String>(),
                        receipt.chain_length
                    );
                    self.fraud.alerts().fire(AlertPayload {
                        event: AlertEvent::SessionSealed,
                        session_id: self.config.session_id.clone(),
                        timestamp_ms: chrono::Utc::now().timestamp_millis(),
                        human_user_id: None,
                        agent_identifier: None,
                        risk_score: None,
                        mode: None,
                        reasons: None,
                        substrate_anchor: Some(receipt.anchor_id),
                        hats_proof: None,
                        recommended_action: None,
                        extra: Some(json!({"chain_length": receipt.chain_length})),
                    });
                }
                Ok(None) => {
                    tracing::debug!("no transcript activity to seal");
                }
                Err(e) => {
                    tracing::warn!("transcript seal failed: {}", e);
                }
            }
        }

        // Fire session_ended
        self.fraud.alerts().fire(AlertPayload {
            event: AlertEvent::SessionEnded,
            session_id: self.config.session_id.clone(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            human_user_id: None,
            agent_identifier: None,
            risk_score: None,
            mode: None,
            reasons: None,
            substrate_anchor: None,
            hats_proof: None,
            recommended_action: None,
            extra: None,
        });

        // Drain pending alert deliveries
        self.fraud.alerts().drain(Duration::from_secs(5)).await;
        self.cachee.clear();
        self.fraud.evict_session(&self.config.session_id);
    }

    /// Spawn the periodic observability snapshot task.
    pub fn spawn_snapshot_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let snap = me.fraud.snapshot(&me.config.session_id);
                let cache_stats = me.cachee.stats();
                if snap.total_calls > 0 {
                    tracing::info!(
                        "snapshot · calls={} writes={} errors={} risk={:.2} mode={} · cachee: hits={} misses={} hit_rate={:.0}% bypass={}",
                        snap.total_calls,
                        snap.write_calls,
                        snap.error_calls,
                        snap.risk_score,
                        snap.mode.as_str(),
                        cache_stats.hits,
                        cache_stats.misses,
                        cache_stats.hit_rate() * 100.0,
                        cache_stats.bypass_count,
                    );
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

async fn handle_request(server: Arc<Server>, request: Request) -> Option<Response> {
    let is_notification = request.is_notification();
    let id = request.id.clone().unwrap_or(Value::Null);

    let result = match request.method.as_str() {
        "initialize" => handle_initialize(&server, request.params).await,
        "initialized" | "notifications/initialized" => {
            tracing::debug!("client sent initialized notification");
            if is_notification {
                return None;
            }
            Ok(Value::Null)
        }
        "tools/list" => handle_list_tools(&server).await,
        "tools/call" => handle_call_tool(&server, request.params).await,
        "ping" => Ok(json!({})),
        "shutdown" => {
            tracing::info!("client requested shutdown");
            Ok(Value::Null)
        }
        other => {
            tracing::warn!("unknown method: {}", other);
            if is_notification {
                return None;
            }
            return Some(Response::error(
                id,
                error_codes::METHOD_NOT_FOUND,
                format!("method not found: {}", other),
            ));
        }
    };

    if is_notification {
        return None;
    }

    Some(match result {
        Ok(value) => Response::success(id, value),
        Err(e) => {
            tracing::warn!("request failed: {}", e);
            Response::error(id, error_codes::INTERNAL_ERROR, e.to_string())
        }
    })
}

async fn handle_initialize(server: &Arc<Server>, params: Option<Value>) -> Result<Value> {
    let _params: InitializeParams = match params {
        Some(p) => serde_json::from_value(p)?,
        None => InitializeParams {
            protocol_version: "2025-06-18".into(),
            capabilities: Value::Null,
            client_info: None,
        },
    };

    let hats = server.hats.read();
    let instructions = hats.as_ref().map(|r| {
        format!(
            "H33 MCP server v{} · HATS Tier {} · proof={}",
            SERVER_VERSION,
            r.tier,
            r.proof_short()
        )
    });

    let result = InitializeResult {
        protocol_version: "2025-06-18".into(),
        server_info: ServerInfo {
            name: SERVER_NAME.into(),
            version: SERVER_VERSION.into(),
        },
        capabilities: ServerCapabilities {
            tools: ToolsCapability { list_changed: false },
        },
        instructions,
    };

    Ok(serde_json::to_value(result)?)
}

async fn handle_list_tools(server: &Arc<Server>) -> Result<Value> {
    let tools = server.tools.list();
    let result = ListToolsResult { tools };
    Ok(serde_json::to_value(result)?)
}

async fn handle_call_tool(server: &Arc<Server>, params: Option<Value>) -> Result<Value> {
    let params_raw = params.unwrap_or(Value::Null);
    let params: CallToolParams = serde_json::from_value(params_raw)
        .map_err(|e| crate::Error::InvalidArgument(format!("tools/call params: {}", e)))?;

    let tool = match server.tools.get(&params.name) {
        Some(t) => t,
        None => {
            // Unknown tool → feed risk score, return binary not_found
            server
                .fraud
                .report_event(&server.config.session_id, RiskEvent::UnknownTool);
            return Ok(serde_json::to_value(CallToolResult {
                content: vec![ToolContent::text(
                    serde_json::to_string(&json!({"error": "not_found"}))?,
                )],
                is_error: true,
            })?);
        }
    };

    let tool_call_id = Uuid::new_v4().to_string();
    let is_write = crate::cachee::flu::is_write_tool(&params.name);

    // Fraud evaluation
    let verdict = server.fraud.evaluate_call(
        &server.config.session_id,
        &params.name,
        &tool_call_id,
        is_write,
    );

    if !verdict.allowed {
        let rejection = verdict
            .rejection
            .as_ref()
            .map(|r| r.error)
            .unwrap_or("denied");
        return Ok(serde_json::to_value(CallToolResult {
            content: vec![ToolContent::text(serde_json::to_string(
                &json!({"error": rejection}),
            )?)],
            is_error: true,
        })?);
    }

    // Dry-run mode: shadow sessions return synthetic successful responses
    // for write tools without actually hitting the API.
    if verdict.dry_run && is_write {
        server.fraud.record_outcome(&verdict.handle, false);
        return Ok(serde_json::to_value(CallToolResult::success_text(
            serde_json::to_string(&json!({
                "mode": "shadow_dry_run",
                "note": "Session is in shadow mode due to anomalous behavior. Writes are dry-run. Human review required.",
            }))?,
        ))?);
    }

    // CacheeFlu hit path for reads
    if !is_write {
        if let Some(cached) = server.cachee.get(&params.name, &params.arguments) {
            server.fraud.record_outcome(&verdict.handle, false);
            return Ok(serde_json::to_value(CallToolResult::success_text(
                serde_json::to_string_pretty(&cached)?,
            ))?);
        }
    }

    // Check capability on the token. The dispatcher trusts that the server
    // started with a valid cka_* token whose capabilities are known; this
    // check is defense-in-depth for tools that require specific bits.
    // In this server, token parsing happens once at startup and is persisted
    // in the fraud guard's session secret derivation — we don't re-verify
    // the token on every call. The real enforcement is the H33 backend
    // checking the agent token on every downstream API call.

    // Build the tool context
    let ctx = ToolContext {
        api: Arc::clone(&server.api),
        cachee: Arc::clone(&server.cachee),
        fraud_guard: Arc::clone(&server.fraud),
    };

    // Execute the tool handler
    let outcome = (tool.handler)(ctx, params.arguments.clone()).await;

    match outcome {
        Ok(value) => {
            // Cache read results on success
            if !is_write {
                server.cachee.set(&params.name, &params.arguments, value.clone());
            }
            server.fraud.record_outcome(&verdict.handle, false);
            Ok(serde_json::to_value(CallToolResult::success_text(
                if value.is_string() {
                    value.as_str().unwrap_or("").to_string()
                } else {
                    serde_json::to_string_pretty(&value)?
                },
            ))?)
        }
        Err(e) => {
            server.fraud.record_outcome(&verdict.handle, true);
            if e.is_auth_boundary() {
                // Binary-minimized error for auth-boundary failures
                Ok(serde_json::to_value(CallToolResult {
                    content: vec![ToolContent::text(serde_json::to_string(
                        &json!({"error": e.binary_code()}),
                    )?)],
                    is_error: true,
                })?)
            } else {
                // Verbose error for in-session failures
                Ok(serde_json::to_value(CallToolResult {
                    content: vec![ToolContent::text(serde_json::to_string(&json!({
                        "error": "tool_error",
                        "message": e.to_string(),
                    }))?)],
                    is_error: true,
                })?)
            }
        }
    }
}
