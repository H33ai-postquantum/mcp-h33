//! Stdio transport for the MCP server.
//!
//! Reads newline-delimited JSON-RPC requests from stdin and writes
//! responses to stdout. Logs go to stderr exclusively so they don't
//! interfere with the protocol stream.

use crate::protocol::jsonrpc::{Request, Response};
use crate::{Error, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use std::sync::Arc;

/// Stdio transport — reads requests from stdin, writes responses to stdout.
///
/// Each message is a complete JSON-RPC envelope on a single line. The
/// transport never blocks the runtime; reads are async and writes are
/// serialized through a single mutex to prevent interleaved output.
#[derive(Debug)]
pub struct StdioTransport {
    stdout: Arc<Mutex<tokio::io::Stdout>>,
}

impl StdioTransport {
    pub fn new() -> Self {
        Self {
            stdout: Arc::new(Mutex::new(tokio::io::stdout())),
        }
    }

    /// Run the receive loop. The supplied handler is invoked for each
    /// parsed request. Notifications (requests with no id) are dispatched
    /// to the handler but generate no response.
    ///
    /// The loop terminates on EOF or on a fatal protocol error.
    pub async fn run<F, Fut>(&self, mut handler: F) -> Result<()>
    where
        F: FnMut(Request) -> Fut + Send,
        Fut: std::future::Future<Output = Option<Response>> + Send,
    {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut buf = String::new();

        loop {
            buf.clear();
            let bytes = reader.read_line(&mut buf).await?;
            if bytes == 0 {
                tracing::info!("stdin closed, shutting down transport");
                return Ok(());
            }
            let line = buf.trim();
            if line.is_empty() {
                continue;
            }

            tracing::trace!("recv: {}", line);

            let request: Request = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("parse error: {}", e);
                    let response = Response::error(
                        serde_json::Value::Null,
                        crate::protocol::jsonrpc::error_codes::PARSE_ERROR,
                        format!("parse error: {}", e),
                    );
                    self.send(&response).await?;
                    continue;
                }
            };

            if let Some(response) = handler(request).await {
                self.send(&response).await?;
            }
        }
    }

    /// Serialize and write a single response to stdout. Mutex-guarded to
    /// prevent interleaved writes from concurrent dispatch tasks.
    pub async fn send(&self, response: &Response) -> Result<()> {
        let json = serde_json::to_string(response).map_err(Error::from)?;
        tracing::trace!("send: {}", json);
        let mut out = self.stdout.lock().await;
        out.write_all(json.as_bytes()).await?;
        out.write_all(b"\n").await?;
        out.flush().await?;
        Ok(())
    }
}

impl Default for StdioTransport {
    fn default() -> Self {
        Self::new()
    }
}
