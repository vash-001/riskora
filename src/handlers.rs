use axum::{extract::{Path, State}, Json};
use sqlx::SqlitePool;
use crate::models::{PremiumResponse, IpPath, ReportPayload};
use crate::engine::DecisionEngine;

pub async fn decision_signup(Path(path): Path<IpPath>) -> Json<PremiumResponse> {
    let response = DecisionEngine::evaluate(&path.ip, "signup");
    Json(response)
}

pub async fn decision_payment(Path(path): Path<IpPath>) -> Json<PremiumResponse> {
    let response = DecisionEngine::evaluate(&path.ip, "payment");
    Json(response)
}

pub async fn get_ip(Path(path): Path<IpPath>) -> Json<serde_json::Value> {
     let resp = DecisionEngine::evaluate(&path.ip, "generic");
     let json = serde_json::json!({
         "ip": resp.ip,
         "risk_score": resp.risk_score,
         "risk_level": resp.risk_level,
         "signals": resp.signals,
         "network": resp.network,
         "location": resp.location
     });
     Json(json)
}

// THE MOAT: Collect reports dynamically and inject them into SQLite
pub async fn handle_report(State(pool): State<SqlitePool>, Json(payload): Json<ReportPayload>) -> Json<serde_json::Value> {
    let result = sqlx::query("INSERT OR REPLACE INTO reports (ip, source, reported_at) VALUES (?, ?, CURRENT_TIMESTAMP)")
        .bind(&payload.ip)
        .bind(&payload.source)
        .execute(&pool).await;

    match result {
        Ok(_) => Json(serde_json::json!({
            "status": "success", 
            "message": "IP recorded into the Private Intelligence Datastore.",
            "ip": payload.ip
        })),
        Err(e) => {
            println!("SQLite Insert Error: {}", e);
            Json(serde_json::json!({"status": "error", "message": "Failed to catalog Intelligence."}))
        }
    }
}
