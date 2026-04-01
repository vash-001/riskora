mod models;
mod engine;
mod handlers;
mod auth;

use axum::{routing::{get, post}, Router, middleware};
use tower_http::cors::{Any, CorsLayer};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::sync::Arc;
use crate::engine::DecisionEngine;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub engine: Arc<DecisionEngine>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let _ = std::fs::create_dir_all("data");
    
    // 1. Initialize Intelligence Moat (SQLite)
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(SqliteConnectOptions::new().filename("data/private_intel.db").create_if_missing(true))
        .await.unwrap();

    // Native Database Hardening
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS reports (ip TEXT PRIMARY KEY, source TEXT, reported_at DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&pool).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS api_keys (key TEXT PRIMARY KEY, plan TEXT, daily_limit INTEGER, used_today INTEGER, last_reset DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&pool).await;
    let _ = sqlx::query("INSERT OR IGNORE INTO api_keys (key, plan, daily_limit, used_today) VALUES ('sk_live_test', 'free', 100, 0)").execute(&pool).await;

    // 2. Initialize The Sentinel Core (The Massive Build)
    let engine = Arc::new(DecisionEngine::new());
    
    let state = AppState {
        pool: pool.clone(),
        engine,
    };

    println!("🏛️  Sentinel Core & Auth Database Connected.");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Endpoints for high-gravity fraud prevention
    let api_routes = Router::new()
        .route("/v1/ip/:ip", get(handlers::get_ip))
        .route("/v1/decision/signup/:ip", get(handlers::decision_signup))
        .route("/v1/decision/payment/:ip", get(handlers::decision_payment))
        .route_layer(middleware::from_fn_with_state(pool, auth::auth_middleware));

    let app = Router::new()
        .merge(api_routes)
        .route("/v1/report", post(handlers::handle_report))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Riskora SENTINEL API running on port 3000");
    println!("🧪 Autopsy Entry: http://localhost:3000/v1/ip/8.8.8.8");
    
    axum::serve(listener, app).await.unwrap();
}
