mod models;
mod engine;
mod handlers;
mod auth;

use axum::{routing::{get, post}, Router, middleware};
use tower_http::cors::{Any, CorsLayer};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[tokio::main]
async fn main() {
    // Setup standard TRACING logging
    tracing_subscriber::fmt::init();

    // The Moat: Intelligence DB Folder Initialization
    let _ = std::fs::create_dir_all("data");
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(SqliteConnectOptions::new().filename("data/private_intel.db").create_if_missing(true))
        .await.unwrap();

    // 🛡️ Create Auth & Report Tables (Native Initialization)
    sqlx::query("CREATE TABLE IF NOT EXISTS reports (ip TEXT PRIMARY KEY, source TEXT, reported_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        .execute(&pool).await.unwrap();
    
    sqlx::query("CREATE TABLE IF NOT EXISTS api_keys (key TEXT PRIMARY KEY, plan TEXT, daily_limit INTEGER, used_today INTEGER, last_reset DATETIME DEFAULT CURRENT_TIMESTAMP)")
        .execute(&pool).await.unwrap();

    // 🔑 Insert Test Key for Verification (Free Plan: 5 request limit for testing)
    // Using runtime query instead of query! macro to avoid build-time DB requirement
    let _ = sqlx::query("INSERT OR IGNORE INTO api_keys (key, plan, daily_limit, used_today) VALUES (?, ?, ?, ?)")
        .bind("sk_live_test")
        .bind("free")
        .bind(5)
        .bind(0)
        .execute(&pool).await;

    println!("💾 Private SQLite Moat & Auth Database Connected.");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Define premium use-case endpoints and Community Feeds
    let api_routes = Router::new()
        .route("/v1/ip/:ip", get(handlers::get_ip))
        .route("/v1/decision/signup/:ip", get(handlers::decision_signup))
        .route("/v1/decision/payment/:ip", get(handlers::decision_payment))
        .route_layer(middleware::from_fn_with_state(pool.clone(), auth::auth_middleware));

    let app = Router::new()
        .merge(api_routes)
        .route("/v1/report", post(handlers::handle_report)) // Keeping report OUT of auth for honeypot ease
        .layer(cors)
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Riskora Premium API running on http://0.0.0.0:3000");
    println!("🔑 Test Key: sk_live_test (Limit: 5)");
    println!("🧪 Try: curl -H 'Authorization: Bearer sk_live_test' http://localhost:3000/v1/decision/signup/1.1.1.1");
    
    axum::serve(listener, app).await.unwrap();
}
