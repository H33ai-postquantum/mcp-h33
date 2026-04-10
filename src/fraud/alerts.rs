//! Customer Webhook Alert Pipeline
//!
//! Fires HMAC-SHA3-256 signed webhooks to the customer-configured endpoint
//! on anomaly events, mode changes, session revocations, and tenant
//! isolation violations. Exponential backoff retry, dead-letter queue
//! on persistent failure.

use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use sha3::Sha3_256;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

type HmacSha3 = Hmac<Sha3_256>;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertEvent {
    SessionStarted,
    SessionEnded,
    ModeChanged,
    AnomalyDetected,
    SessionRevoked,
    TenantIsolationViolation,
    TranscriptAnchor,
    SessionSealed,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertPayload {
    pub event: AlertEvent,
    pub session_id: String,
    pub timestamp_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substrate_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hats_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct AlertPipelineConfig {
    pub webhook_url: Option<String>,
    pub signing_secret: String,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub timeout: Duration,
}

impl AlertPipelineConfig {
    pub fn new(webhook_url: Option<String>, signing_secret: String) -> Self {
        Self {
            webhook_url,
            signing_secret,
            max_retries: 6,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(32),
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)] // fields are read via Debug derive when logging DLQ
struct DeadLetter {
    payload: AlertPayload,
    error: String,
    at_ms: i64,
}

#[derive(Debug)]
pub struct AlertPipeline {
    config: AlertPipelineConfig,
    client: reqwest::Client,
    inflight: AtomicUsize,
    dead_letters: Mutex<Vec<DeadLetter>>,
}

impl AlertPipeline {
    pub fn new(config: AlertPipelineConfig) -> Arc<Self> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("h33-mcp-alert/0.1")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Arc::new(Self {
            config,
            client,
            inflight: AtomicUsize::new(0),
            dead_letters: Mutex::new(Vec::new()),
        })
    }

    /// Sign a payload with HMAC-SHA3-256. Used by both delivery and tests.
    /// HMAC over any key length is infallible; the Err branch is unreachable
    /// in practice but we handle it by falling through to a zero-key MAC
    /// rather than panicking.
    pub fn sign(&self, payload_json: &str, timestamp_ms: i64) -> String {
        let key_bytes = self.config.signing_secret.as_bytes();
        let mut mac = match HmacSha3::new_from_slice(key_bytes) {
            Ok(m) => m,
            Err(_) => {
                // HMAC-SHA3-256 accepts any key length, so this branch is
                // unreachable in practice. If we ever hit it, fall back to
                // an empty-keyed HMAC rather than panicking.
                match HmacSha3::new_from_slice(&[0u8; 32]) {
                    Ok(m) => m,
                    Err(_) => return String::new(),
                }
            }
        };
        mac.update(b"h33-mcp-alert/v1");
        mac.update(&[0u8]);
        mac.update(timestamp_ms.to_string().as_bytes());
        mac.update(&[0u8]);
        mac.update(payload_json.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Fire an alert. Returns immediately — delivery happens async with retry.
    /// If no webhook URL is configured, the alert is logged locally only.
    pub fn fire(self: &Arc<Self>, payload: AlertPayload) {
        tracing::info!(
            event = ?payload.event,
            session = %payload.session_id,
            risk = ?payload.risk_score,
            "alert"
        );

        let Some(_url) = self.config.webhook_url.clone() else {
            return;
        };

        self.inflight.fetch_add(1, Ordering::Relaxed);
        let pipeline = Arc::clone(self);
        tokio::spawn(async move {
            let result = pipeline.deliver(payload).await;
            pipeline.inflight.fetch_sub(1, Ordering::Relaxed);
            if let Err(e) = result {
                tracing::warn!("alert delivery: {}", e);
            }
        });
    }

    async fn deliver(&self, payload: AlertPayload) -> Result<(), String> {
        let Some(url) = &self.config.webhook_url else {
            return Ok(());
        };
        let json = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
        let timestamp_ms = chrono::Utc::now().timestamp_millis();
        let signature = self.sign(&json, timestamp_ms);

        let mut backoff = self.config.initial_backoff;
        let mut last_error = String::new();

        for attempt in 0..=self.config.max_retries {
            let req = self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .header("X-H33-Signature", &signature)
                .header("X-H33-Timestamp", timestamp_ms.to_string())
                .header("X-H33-Event", format!("{:?}", payload.event))
                .header("X-H33-Session", &payload.session_id)
                .body(json.clone());

            match req.send().await {
                Ok(res) if res.status().is_success() => {
                    tracing::debug!(
                        "alert delivered · {:?} · attempt={}",
                        payload.event,
                        attempt + 1
                    );
                    return Ok(());
                }
                Ok(res) => {
                    let status = res.status();
                    last_error = format!("{}", status);
                    // 4xx (other than 408/429) are non-retryable
                    if status.is_client_error()
                        && status != reqwest::StatusCode::REQUEST_TIMEOUT
                        && status != reqwest::StatusCode::TOO_MANY_REQUESTS
                    {
                        break;
                    }
                }
                Err(e) => {
                    last_error = e.to_string();
                }
            }

            if attempt < self.config.max_retries {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(self.config.max_backoff);
            }
        }

        // All retries exhausted → DLQ
        let mut dl = self.dead_letters.lock();
        dl.push(DeadLetter {
            payload: payload.clone(),
            error: last_error.clone(),
            at_ms: chrono::Utc::now().timestamp_millis(),
        });
        tracing::warn!(
            "alert dead-lettered · {:?} · session={} · error={}",
            payload.event,
            payload.session_id,
            last_error
        );
        Err(last_error)
    }

    pub fn dead_letter_count(&self) -> usize {
        self.dead_letters.lock().len()
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Wait for all in-flight alert deliveries to complete or timeout.
    pub async fn drain(&self, timeout: Duration) {
        let start = tokio::time::Instant::now();
        while self.inflight() > 0 && start.elapsed() < timeout {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
