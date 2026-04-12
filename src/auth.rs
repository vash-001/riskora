use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use moka::sync::Cache;
use sqlx::{SqlitePool, Row};
use std::time::Duration;
use crate::models::{ApiKeyInfo, AuthError};
use lazy_static::lazy_static;
use chrono::Utc;

lazy_static! {
    pub static ref AUTH_CACHE: Cache<String, ApiKeyInfo> = Cache::builder()
        .max_capacity(100_000)
        .time_to_live(Duration::from_secs(60))
        .build();
}

pub async fn auth_middleware(
    State(pool): State<SqlitePool>,
    request: Request,
    next: Next,
) -> Response {
    // Extract token as owned String immediately — releases the borrow on `request`
    let token: String = {
        let auth_header = request
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok());

        match auth_header {
            Some(h) if h.starts_with("Bearer ") => h.trim_start_matches("Bearer ").trim().to_string(),
            _ => return unauthorized_response("Missing or invalid Authorization header."),
        }
    };

    // Basic token format sanity check
    if token.len() < 8 || token.len() > 128 {
        return unauthorized_response("Invalid API Key format.");
    }

    // --- Master Admin Secret Bypass ---
    if let Ok(admin_secret) = std::env::var("ADMIN_SECRET") {
        if token == admin_secret {
            let mut request = request; // request is no longer borrowed — safe to move
            request.extensions_mut().insert(token.clone());
            return next.run(request).await;
        }
    }

    let key_info = match AUTH_CACHE.get(&token) {
        Some(info) => info,
        None => {
            let db_key = sqlx::query(
                "SELECT key, plan, daily_limit, used_today, last_reset FROM api_keys WHERE key = ?"
            )
            .bind(&token)
            .fetch_optional(&pool)
            .await;

            match db_key {
                Ok(Some(row)) => {
                    let info = ApiKeyInfo {
                        key: row.get(0),
                        plan: row.get(1),
                        daily_limit: row.get(2),
                        used_today: row.get(3),
                        last_reset: row.get::<Option<String>, _>(4).unwrap_or_default(),
                    };
                    AUTH_CACHE.insert(token.clone(), info.clone());
                    info
                }
                _ => return unauthorized_response("Invalid API Key."),
            }
        }
    };

    // --- Daily Quota Reset Check ---
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let effective_used = if key_info.last_reset != today {
        // Reset counter for today with explicit UTC Date
        let _ = sqlx::query(
            "UPDATE api_keys SET used_today = 0, last_reset = ? WHERE key = ?"
        )
        .bind(&today)
        .bind(&token)
        .execute(&pool)
        .await;
        // Invalidate cache entry
        AUTH_CACHE.invalidate(&token);
        0i64
    } else {
        key_info.used_today
    };

    if effective_used >= key_info.daily_limit {
        return quota_exceeded_response();
    }

    // Increment usage
    if let Err(e) = sqlx::query(
        "UPDATE api_keys SET used_today = used_today + 1 WHERE key = ?"
    )
    .bind(&token)
    .execute(&pool)
    .await
    {
        eprintln!("CRITICAL: Quota Sync Failure: {}", e);
    }

    // Update cache with new usage count
    let mut updated_info = key_info.clone();
    updated_info.used_today = effective_used + 1;
    AUTH_CACHE.insert(token.clone(), updated_info);

    // Pass API key to handlers for logging
    let mut request = request;
    request.extensions_mut().insert(key_info.key.clone());

    next.run(request).await
}

fn unauthorized_response(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "unauthorized".to_string(),
            message: msg.to_string(),
            upgrade_url: "https://riskora.io/pricing".to_string(),
        }),
    )
        .into_response()
}

fn quota_exceeded_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(AuthError {
            error: "quota_exceeded".to_string(),
            message: "You have reached your daily request limit. Upgrade your plan for higher limits.".to_string(),
            upgrade_url: "https://riskora.io/pricing".to_string(),
        }),
    )
        .into_response()
}
