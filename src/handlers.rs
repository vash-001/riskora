use axum::{extract::{Path, State}, Json, Extension};
use crate::models::{PremiumResponse, IpPath, ReportPayload, LogEntry, AdminStats, TopItem, GeoPoint, BlogPost};
use crate::AppState;

async fn log_request(state: &AppState, res: &PremiumResponse, api_key: String) {
    let entry = LogEntry {
        ip: res.ip.clone(),
        action: res.action.clone(),
        profile: res.profile.clone(),
        api_key: api_key,
        lat: Some(res.location.latitude),
        lon: Some(res.location.longitude),
    };
    let _ = state.log_tx.send(entry).await;
}

pub async fn decision_signup(
    State(state): State<AppState>, 
    Extension(api_key): Extension<String>,
    Path(path): Path<IpPath>
) -> Json<PremiumResponse> {
    let response = state.engine.evaluate(&path.ip, "signup");
    log_request(&state, &response, api_key).await;
    Json(response)
}

pub async fn decision_payment(
    State(state): State<AppState>, 
    Extension(api_key): Extension<String>,
    Path(path): Path<IpPath>
) -> Json<PremiumResponse> {
    let response = state.engine.evaluate(&path.ip, "payment");
    log_request(&state, &response, api_key).await;
    Json(response)
}

pub async fn get_ip(
    State(state): State<AppState>, 
    Extension(api_key): Extension<String>,
    Path(path): Path<IpPath>
) -> Json<PremiumResponse> {
     let response = state.engine.evaluate(&path.ip, "generic");
     log_request(&state, &response, api_key).await;
     Json(response)
}

// --- ADMIN & STATS HANDLERS ---

pub async fn admin_get_stats(State(state): State<AppState>) -> Json<AdminStats> {
    let total_24h: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM traffic_logs WHERE created_at > datetime('now', '-1 day')")
        .fetch_one(&state.pool).await.unwrap_or((0,));
    
    let top_ips: Vec<TopItem> = sqlx::query_as("SELECT ip as label, COUNT(*) as count FROM traffic_logs GROUP BY ip ORDER BY count DESC LIMIT 5")
        .fetch_all(&state.pool).await.unwrap_or_default();

    let top_keys: Vec<TopItem> = sqlx::query_as("SELECT api_key as label, COUNT(*) as count FROM traffic_logs GROUP BY api_key ORDER BY count DESC LIMIT 5")
        .fetch_all(&state.pool).await.unwrap_or_default();

    let geo_dist: Vec<GeoPoint> = sqlx::query_as("SELECT lat, lon, COUNT(*) as count, 'Global' as country FROM traffic_logs WHERE lat IS NOT NULL GROUP BY lat, lon LIMIT 100")
        .fetch_all(&state.pool).await.unwrap_or_default();

    Json(AdminStats {
        total_requests_24h: total_24h.0,
        top_ips,
        top_keys,
        geo_distribution: geo_dist,
    })
}

// --- BLOG HANDLERS ---

pub async fn get_blog_posts(State(state): State<AppState>) -> Json<Vec<BlogPost>> {
    let posts = sqlx::query_as::<_, BlogPost>("SELECT * FROM blog_posts ORDER BY published_at DESC")
        .fetch_all(&state.pool).await.unwrap_or_default();
    Json(posts)
}

pub async fn admin_create_blog(State(state): State<AppState>, Json(payload): Json<BlogPost>) -> Json<serde_json::Value> {
    let _ = sqlx::query("INSERT INTO blog_posts (title, slug, content, excerpt, author, category) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&payload.title)
        .bind(&payload.slug)
        .bind(&payload.content)
        .bind(&payload.excerpt)
        .bind(&payload.author)
        .bind(&payload.category)
        .execute(&state.pool).await;

    Json(serde_json::json!({"status": "success"}))
}

pub async fn get_blog_post(State(state): State<AppState>, Path(slug): Path<String>) -> Json<Option<BlogPost>> {
    let post = sqlx::query_as::<_, BlogPost>("SELECT * FROM blog_posts WHERE slug = ?")
        .bind(slug)
        .fetch_optional(&state.pool).await.unwrap_or(None);
    Json(post)
}

// THE MOAT: Collect reports dynamically and inject them into SQLite
pub async fn handle_report(State(state): State<AppState>, Json(payload): Json<ReportPayload>) -> Json<serde_json::Value> {
    let result = sqlx::query("INSERT OR REPLACE INTO reports (ip, source, reported_at) VALUES (?, ?, CURRENT_TIMESTAMP)")
        .bind(&payload.ip)
        .bind(&payload.source)
        .execute(&state.pool).await;

    match result {
        Ok(_) => Json(serde_json::json!({
            "status": "success", 
            "message": "Sentinel: IP Catalinked into the Private Moat.",
            "ip": payload.ip
        })),
        Err(e) => {
            println!("Sentinel SQLite Error: {}", e);
            Json(serde_json::json!({"status": "error", "message": "Sentinel Core: Failure to catalog Intelligence."}))
        }
    }
}
