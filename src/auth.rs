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
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => h.trim_start_matches("Bearer "),
        _ => return unauthorized_response("Missing or invalid Authorization header."),
    };

    let key_info = match AUTH_CACHE.get(token) {
        Some(info) => info,
        None => {
            // Using runtime query instead of query_as! macro
            let db_key = sqlx::query("SELECT key, plan, daily_limit, used_today FROM api_keys WHERE key = ?")
                .bind(token)
                .fetch_optional(&pool)
                .await;

            match db_key {
                Ok(Some(row)) => {
                    let info = ApiKeyInfo {
                        key: row.get(0),
                        plan: row.get(1),
                        daily_limit: row.get(2),
                        used_today: row.get(3),
                    };
                    AUTH_CACHE.insert(token.to_string(), info.clone());
                    info
                }
                _ => return unauthorized_response("Invalid API Key."),
            }
        }
    };

    if key_info.used_today >= key_info.daily_limit {
        return quota_exceeded_response();
    }

    // Update Usage in DB
    let _ = sqlx::query("UPDATE api_keys SET used_today = used_today + 1 WHERE key = ?")
        .bind(token)
        .execute(&pool)
        .await;

    // Refresh cache with new usage
    let mut updated_info = key_info.clone();
    updated_info.used_today += 1;
    AUTH_CACHE.insert(token.to_string(), updated_info);

    next.run(request).await
}

fn unauthorized_response(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "unauthorized".to_string(),
            message: msg.to_string(),
            upgrade_url: "riskora.xyz/pricing".to_string(),
        }),
    )
        .into_response()
}

fn quota_exceeded_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(AuthError {
            error: "quota_exceeded".to_string(),
            message: "You have reached your daily quota. Upgrade your plan for higher limits.".to_string(),
            upgrade_url: "riskora.xyz/pricing".to_string(),
        }),
    )
        .into_response()
}
