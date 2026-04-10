//! H33 MCP server — native Rust entry point.
//!
//! Invoked by Claude Code, Cursor, Codex, Aider, or any MCP-capable AI
//! coding agent over stdio. Speaks JSON-RPC 2.0 line-delimited over
//! stdin/stdout. All logging goes to stderr so it doesn't corrupt the
//! protocol stream.
//!
//! Lifecycle:
//!   1. Parse CLI args / environment
//!   2. Validate the cka_* agent token format (ck_live_* and ck_test_* rejected)
//!   3. Build the server state (API client, CacheeFlu, FraudGuard, tool registry)
//!   4. Self-register with HATS Tier 1 (graceful degradation on failure)
//!   5. Start the substrate-anchored transcript chain (Patent Extension 22)
//!   6. Fire the session_started alert to the customer webhook
//!   7. Spawn the periodic snapshot task
//!   8. Run the stdio JSON-RPC dispatch loop until EOF or signal
//!   9. On shutdown: seal the transcript, drain alerts, clear the cache
//!
//! Architectural rule: **Agents hold `cka_*`. Servers hold `ck_live_*`.
//! They are never the same thing.**

use clap::Parser;
use h33_mcp::config::{CliArgs, Config, SharedConfig};
use h33_mcp::server::Server;
use h33_mcp::{SERVER_NAME, SERVER_VERSION};
use std::io::IsTerminal;
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    // Parse CLI args; falls back to H33_* environment variables.
    let args = CliArgs::parse();
    let config = Config::from_args(args);

    // Initialize tracing — every log goes to stderr so it never corrupts
    // the JSON-RPC protocol stream on stdout.
    let filter = EnvFilter::try_new(&config.log).unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_level(true)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    tracing::info!(
        "{}/{} starting · api={} · session={}...",
        SERVER_NAME,
        SERVER_VERSION,
        config.api_base,
        &config.session_id.chars().take(8).collect::<String>(),
    );

    // Validate the agent token format BEFORE doing anything else.
    // This is the architectural rule: no ck_live_* ever enters an agent context.
    if let Err(e) = config.validate() {
        eprintln!();
        eprintln!("H33 MCP refused to start:");
        eprintln!();
        eprintln!("  {}", e);
        eprintln!();
        eprintln!("Docs: https://h33.ai/docs/agent-token-architecture");
        std::process::exit(1);
    }

    let shared: SharedConfig = Arc::new(config);
    let server = Server::new(Arc::clone(&shared)).await?;

    // Self-register with HATS Tier 1 — graceful degradation on failure.
    server.register_hats().await;

    // Start the substrate-anchored session transcript chain.
    let transcript_task = server.start_transcript();

    // Fire the initial session_started webhook alert.
    server.fire_session_started();

    // Spawn the periodic observability snapshot task.
    let snapshot_task = server.spawn_snapshot_task();

    tracing::info!(
        "ready · 20 tools registered · fraud protection: nullifier + anomaly + risk + binary minimization · cachee: in-process W-TinyLFU · hats: {}",
        if shared.disable_hats { "disabled" } else { "tier 1" }
    );

    // Install a signal handler for graceful shutdown.
    let shutdown_server = Arc::clone(&server);
    let signal_task = tokio::spawn(async move {
        let mut sigint = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to install SIGINT handler: {}", e);
                return;
            }
        };
        let mut sigterm = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to install SIGTERM handler: {}", e);
                return;
            }
        };
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("received SIGINT");
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM");
            }
        }
        shutdown_server.shutdown().await;
        std::process::exit(0);
    });

    // Run the stdio dispatch loop. Returns on EOF (stdin closed) or error.
    let run_result = Arc::clone(&server).run().await;

    // Normal shutdown (EOF)
    if let Some(t) = transcript_task {
        t.abort();
    }
    snapshot_task.abort();
    signal_task.abort();
    server.shutdown().await;

    run_result.map_err(|e| anyhow::anyhow!(e.to_string()))
}
