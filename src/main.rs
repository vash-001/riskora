mod models;
mod engine;
mod handlers;
mod auth;
mod webhooks;
mod updater;

use axum::{routing::{get, post}, Router, middleware};
use tower_http::cors::{CorsLayer, AllowOrigin};
use axum::http::{HeaderValue, Method};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::sync::Arc;
use std::time::Duration;
use crate::engine::DecisionEngine;

use tokio::sync::mpsc;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub engine: Arc<DecisionEngine>,
    pub log_tx: mpsc::Sender<models::LogEntry>,
    pub webhook_tx: mpsc::Sender<webhooks::WebhookPayload>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let _ = std::fs::create_dir_all("data");

    // 1. Initialize Intelligence Moat (SQLite)
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(
            SqliteConnectOptions::new()
                .filename("data/private_intel.db")
                .create_if_missing(true)
                .pragma("journal_mode", "WAL")
                .pragma("synchronous", "NORMAL"),
        )
        .await
        .expect("CRITICAL: Cannot connect to SQLite database");

    // Schema Initialization
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS reports (ip TEXT PRIMARY KEY, source TEXT, reported_at DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&pool).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS api_keys (key TEXT PRIMARY KEY, plan TEXT, daily_limit INTEGER, used_today INTEGER DEFAULT 0, last_reset DATE DEFAULT (date('now')))").execute(&pool).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS traffic_logs (id INTEGER PRIMARY KEY, ip TEXT, action TEXT, profile TEXT, api_key TEXT, lat REAL, lon REAL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&pool).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS webhooks_config (api_key TEXT PRIMARY KEY, url TEXT, secret TEXT)").execute(&pool).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS blog_posts (id INTEGER PRIMARY KEY, title TEXT, slug TEXT UNIQUE, content TEXT, excerpt TEXT, author TEXT, category TEXT, image_url TEXT, published_at DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&pool).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS report_ratelimit (ip TEXT PRIMARY KEY, count INTEGER DEFAULT 1, window_start DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&pool).await;

    // Performance Indexes
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_traffic_created_at ON traffic_logs(created_at)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_traffic_ip ON traffic_logs(ip)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_traffic_api_key ON traffic_logs(api_key)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_reports_reported_at ON reports(reported_at)").execute(&pool).await;

    // Seed test key (only if not exists)
    let _ = sqlx::query("INSERT OR IGNORE INTO api_keys (key, plan, daily_limit, used_today) VALUES ('sk_live_test', 'free', 100, 0)").execute(&pool).await;

    // 2. Setup Background Logger
    let (log_tx, mut log_rx) = mpsc::channel::<models::LogEntry>(1000);
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        while let Some(entry) = log_rx.recv().await {
            let _ = sqlx::query("INSERT INTO traffic_logs (ip, action, profile, api_key, lat, lon) VALUES (?, ?, ?, ?, ?, ?)")
                .bind(entry.ip)
                .bind(entry.action)
                .bind(entry.profile)
                .bind(entry.api_key)
                .bind(entry.lat)
                .bind(entry.lon)
                .execute(&pool_clone)
                .await;
        }
    });

    // 3. Background Velocity Store Cleanup (every 5 minutes)
    // Spawned after engine is created, so we store a reference via Arc

    // 4. Initialize The Sentinel Core
    let engine = Arc::new(DecisionEngine::new());

    // 5. Background velocity store cleanup (Removed, handled by Moka Cache TTL)

    // 6. Threat Auto-Updater Service
    updater::start_threat_updater(engine.threat_table.clone());

    // 7. Webhook Dispatch Service
    let (webhook_tx, webhook_rx) = mpsc::channel::<webhooks::WebhookPayload>(1000);
    webhooks::start_webhook_service(pool.clone(), webhook_rx);

    let state = AppState {
        pool: pool.clone(),
        engine,
        log_tx,
        webhook_tx,
    };

    println!("🏛️  Sentinel Core & Auth Database Connected.");

    // --- CORS (تقييد Origins) ---
    let allowed_origins: Vec<HeaderValue> = {
        let origins_str = std::env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173,http://localhost:4173".to_string());
        origins_str
            .split(',')
            .filter_map(|o| o.trim().parse::<HeaderValue>().ok())
            .collect()
    };

    let cors = if allowed_origins.is_empty() {
        // Development fallback
        CorsLayer::permissive()
    } else {
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(allowed_origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(tower_http::cors::Any)
    };

    // Protected API routes
    let api_routes = Router::new()
        .route("/v1/ip/{ip}", get(handlers::get_ip))
        .route("/v1/decision/signup/{ip}", get(handlers::decision_signup))
        .route("/v1/decision/payment/{ip}", get(handlers::decision_payment))
        .route("/v1/admin/stats", get(handlers::admin_get_stats))
        .route("/v1/admin/blog", post(handlers::admin_create_blog))
        .route("/v1/admin/upload_image", post(handlers::admin_upload_image))
        .route("/v1/report", post(handlers::handle_report))
        .route_layer(middleware::from_fn_with_state(pool, auth::auth_middleware));

    let app = Router::new()
        .merge(api_routes)
        .route("/v1/blog", get(handlers::get_blog_posts))
        .route("/v1/blog/{slug}", get(handlers::get_blog_post))
        .route("/health", get(handlers::health_check))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await
        .unwrap_or_else(|e| panic!("CRITICAL: Cannot bind to {}: {}", addr, e));
    println!("🚀 Riskora SENTINEL API running on port {}", port);
    println!("🧪 Health Check: http://localhost:{}/health", port);

    axum::serve(listener, app).await
        .unwrap_or_else(|e| eprintln!("Server error: {}", e));
}
