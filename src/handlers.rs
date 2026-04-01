use axum::{extract::{Path, State}, Json};
use crate::models::{PremiumResponse, IpPath, ReportPayload};
use crate::AppState;

pub async fn decision_signup(State(state): State<AppState>, Path(path): Path<IpPath>) -> Json<PremiumResponse> {
    let response = state.engine.evaluate(&path.ip, "signup");
    Json(response)
}

pub async fn decision_payment(State(state): State<AppState>, Path(path): Path<IpPath>) -> Json<PremiumResponse> {
    let response = state.engine.evaluate(&path.ip, "payment");
    Json(response)
}

pub async fn get_ip(State(state): State<AppState>, Path(path): Path<IpPath>) -> Json<PremiumResponse> {
     let resp = state.engine.evaluate(&path.ip, "generic");
     Json(resp)
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
