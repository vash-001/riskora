use reqwest::Client;
use serde_json::json;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Clone, Debug)]
pub struct WebhookPayload {
    pub api_key: String,
    pub ip: String,
    pub risk_score: u8,
    pub action: String,
    pub details: String,
}

/// Starts a background listener for webhook dispatching
pub fn start_webhook_service(pool: SqlitePool, mut rx: mpsc::Receiver<WebhookPayload>) {
    tokio::spawn(async move {
        let client = Client::new();
        
        while let Some(payload) = rx.recv().await {
            // Check if this API Key has a webhook registered
            let webhook_info: Option<(String, String)> = sqlx::query_as(
                "SELECT url, secret FROM webhooks_config WHERE api_key = ?"
            )
            .bind(&payload.api_key)
            .fetch_optional(&pool)
            .await
            .unwrap_or(None);

            if let Some((url, secret)) = webhook_info {
                // Determine a generic JSON payload
                let body = json!({
                    "event": "risk.high",
                    "data": {
                        "ip": payload.ip,
                        "risk_score": payload.risk_score,
                        "action": payload.action,
                        "details": payload.details
                    }
                });
                
                let body_str = body.to_string();
                let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                    .expect("HMAC can take key of any size");
                mac.update(body_str.as_bytes());
                let signature = hex::encode(mac.finalize().into_bytes());

                // Send the payload asynchronously without blocking the core
                let req_url = url.clone();
                let client_clone = client.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = client_clone.post(&req_url)
                        .header("X-Riskora-Signature", signature)
                        .header("Content-Type", "application/json")
                        .body(body_str)
                        .send().await {
                        eprintln!("⚠️ Webhook dispatch failed for url {}: {}", req_url, e);
                    }
                });
            }
        }
    });
}
