use axum::{extract::{Path, State}, Json, Extension, http::StatusCode};
use crate::models::{PremiumResponse, IpPath, ReportPayload, LogEntry, AdminStats, TopItem, GeoPoint, BlogPost, HealthStatus, CloudinaryUploadPayload};
use crate::AppState;
use sha1::Digest;
use std::net::IpAddr;

// --- IP Validation Helper ---
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

async fn log_request(state: &AppState, res: &PremiumResponse, api_key: String) {
    let entry = LogEntry {
        ip: res.ip.clone(),
        action: res.action.clone(),
        profile: res.profile.clone(),
        api_key: api_key.clone(),
        lat: Some(res.location.latitude),
        lon: Some(res.location.longitude),
    };
    let _ = state.log_tx.send(entry).await;

    // Trigger Webhook if high risk (>= 80)
    if res.risk_score >= 80 {
        let payload = crate::webhooks::WebhookPayload {
            api_key,
            ip: res.ip.clone(),
            risk_score: res.risk_score,
            action: res.action.clone(),
            details: res.reason.clone(),
        };
        let _ = state.webhook_tx.send(payload).await;
    }
}

pub async fn decision_signup(
    State(state): State<AppState>,
    Extension(api_key): Extension<String>,
    Path(path): Path<IpPath>,
) -> Result<Json<PremiumResponse>, StatusCode> {
    if !is_valid_ip(&path.ip) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let response = state.engine.evaluate(&path.ip, "signup");
    log_request(&state, &response, api_key).await;
    Ok(Json(response))
}

pub async fn decision_payment(
    State(state): State<AppState>,
    Extension(api_key): Extension<String>,
    Path(path): Path<IpPath>,
) -> Result<Json<PremiumResponse>, StatusCode> {
    if !is_valid_ip(&path.ip) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let response = state.engine.evaluate(&path.ip, "payment");
    log_request(&state, &response, api_key).await;
    Ok(Json(response))
}

pub async fn get_ip(
    State(state): State<AppState>,
    Extension(api_key): Extension<String>,
    Path(path): Path<IpPath>,
) -> Result<Json<PremiumResponse>, StatusCode> {
    if !is_valid_ip(&path.ip) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let response = state.engine.evaluate(&path.ip, "generic");
    log_request(&state, &response, api_key).await;
    Ok(Json(response))
}

// --- HEALTH CHECK ---

pub async fn health_check(State(state): State<AppState>) -> Json<HealthStatus> {
    let db_ok = sqlx::query("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    let (v4, v6) = state.engine.threat_table.load().len();
    let threat_rules = v4 + v6;

    Json(HealthStatus {
        status: if db_ok { "healthy".to_string() } else { "degraded".to_string() },
        database: if db_ok { "connected".to_string() } else { "error".to_string() },
        threat_rules,
        version: "1.0.0".to_string(),
    })
}

// --- ADMIN & STATS HANDLERS ---

pub async fn admin_get_stats(
    Extension(api_key): Extension<String>,
    State(state): State<AppState>
) -> Result<Json<AdminStats>, (StatusCode, String)> {
    
    // STRICT ADMIN CHECK
    let admin_secret = std::env::var("ADMIN_SECRET").unwrap_or_default();
    if api_key != admin_secret || admin_secret.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized Admin Access".into()));
    }

    let total_24h: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM traffic_logs WHERE created_at > datetime('now', '-1 day')"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0,));

    let top_ips: Vec<TopItem> = sqlx::query_as(
        "SELECT ip as label, COUNT(*) as count FROM traffic_logs GROUP BY ip ORDER BY count DESC LIMIT 5"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let top_keys: Vec<TopItem> = sqlx::query_as(
        "SELECT api_key as label, COUNT(*) as count FROM traffic_logs GROUP BY api_key ORDER BY count DESC LIMIT 5"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let geo_dist: Vec<GeoPoint> = sqlx::query_as(
        "SELECT lat, lon, COUNT(*) as count, 'Global' as country FROM traffic_logs WHERE lat IS NOT NULL GROUP BY lat, lon LIMIT 100"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let time_series: Vec<TopItem> = sqlx::query_as(
        "SELECT strftime('%Y-%m-%d', created_at) as label, COUNT(*) as count FROM traffic_logs WHERE created_at > datetime('now', '-7 days') GROUP BY label ORDER BY label ASC"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    Ok(Json(AdminStats {
        total_requests_24h: total_24h.0,
        top_ips,
        top_keys,
        geo_distribution: geo_dist,
        time_series,
    }))
}

// --- BLOG HANDLERS ---

pub async fn get_blog_posts(State(state): State<AppState>) -> Json<Vec<BlogPost>> {
    let posts = sqlx::query_as::<_, BlogPost>(
        "SELECT * FROM blog_posts ORDER BY published_at DESC"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    Json(posts)
}

pub async fn admin_create_blog(
    Extension(api_key): Extension<String>,
    State(state): State<AppState>,
    Json(payload): Json<BlogPost>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // STRICT ADMIN CHECK
    let admin_secret = std::env::var("ADMIN_SECRET").unwrap_or_default();
    if api_key != admin_secret || admin_secret.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized Admin Access".into()));
    }

    // Validate required fields
    if payload.title.trim().is_empty() || payload.slug.trim().is_empty() {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Title and slug are required."
        })));
    }

    let result = sqlx::query(
        "INSERT INTO blog_posts (title, slug, content, excerpt, author, category, image_url) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&payload.title.trim())
    .bind(&payload.slug.trim().to_lowercase())
    .bind(&payload.content)
    .bind(&payload.excerpt)
    .bind(&payload.author)
    .bind(&payload.category)
    .bind(&payload.image_url)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => Ok(Json(serde_json::json!({"status": "success"}))),
        Err(e) if e.to_string().contains("UNIQUE") => Ok(Json(serde_json::json!({
            "status": "error",
            "message": "A post with this slug already exists."
        }))),
        Err(_) => Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Failed to create post."
        }))),
    }
}

pub async fn get_blog_post(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Json<Option<BlogPost>> {
    let post = sqlx::query_as::<_, BlogPost>(
        "SELECT * FROM blog_posts WHERE slug = ?"
    )
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);
    Json(post)
}

// --- THE MOAT: Community Reports with Rate Limiting ---

pub async fn handle_report(
    State(state): State<AppState>,
    Json(payload): Json<ReportPayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate IP format
    if !is_valid_ip(&payload.ip) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": "Invalid IP address format."
            })),
        );
    }

    // Validate source field
    let valid_sources = ["honeypot", "community", "manual"];
    if !valid_sources.contains(&payload.source.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": "Invalid source. Must be one of: honeypot, community, manual."
            })),
        );
    }

    // Rate limit: max 10 reports per IP per hour
    let count_result: Result<(i64,), _> = sqlx::query_as(
        "SELECT COUNT(*) FROM reports WHERE ip = ? AND reported_at > datetime('now', '-1 hour')"
    )
    .bind(&payload.ip)
    .fetch_one(&state.pool)
    .await;

    if let Ok((count,)) = count_result {
        if count >= 10 {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "status": "error",
                    "message": "Rate limit: This IP has been reported too many times recently."
                })),
            );
        }
    }

    let result = sqlx::query(
        "INSERT OR REPLACE INTO reports (ip, source, reported_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
    )
    .bind(&payload.ip)
    .bind(&payload.source)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "message": "Sentinel: IP catalogued into the Private Moat.",
                "ip": payload.ip
            })),
        ),
        Err(e) => {
            eprintln!("Sentinel SQLite Error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "error",
                    "message": "Sentinel Core: Failed to catalogue intelligence."
                })),
            )
        }
    }
}

pub async fn admin_upload_image(
    Extension(api_key): Extension<String>,
    Json(payload): Json<CloudinaryUploadPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // STRICT ADMIN CHECK
    let admin_secret = std::env::var("ADMIN_SECRET").unwrap_or_default();
    if api_key != admin_secret || admin_secret.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized Admin Access".into()));
    }

    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().to_string();

    let api_secret = std::env::var("CLOUDINARY_API_SECRET")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cloudinary API Secret not configured".to_string()))?;
    let api_key_cloudinary = std::env::var("CLOUDINARY_API_KEY")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cloudinary API Key not configured".to_string()))?;
    let cloud_name = std::env::var("CLOUDINARY_CLOUD_NAME")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cloudinary Cloud Name not configured".to_string()))?;

    let str_to_sign = format!("timestamp={}{}", timestamp, api_secret);
    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, str_to_sign.as_bytes());
    let signature = hex::encode(hasher.finalize());

    let mut form = std::collections::HashMap::new();
    form.insert("file", payload.base64_image);
    form.insert("api_key", api_key_cloudinary);
    form.insert("timestamp", timestamp);
    form.insert("signature", signature);

    let client = reqwest::Client::new();
    let res = client.post(format!("https://api.cloudinary.com/v1_1/{}/image/upload", cloud_name))
        .form(&form)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let json_res: serde_json::Value = res.json().await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(url) = json_res.get("secure_url") {
        return Ok(Json(serde_json::json!({
            "status": "success",
            "url": url
        })));
    }

    Err((StatusCode::INTERNAL_SERVER_ERROR, "Cloudinary upload failed".into()))
}
