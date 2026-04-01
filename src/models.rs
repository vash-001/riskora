use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    RequireCaptcha,
    Flag,
    Block,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PremiumResponse {
    pub ip: String,
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub decision: Decision,
    pub confidence: u8,
    pub reason: String,
    pub action: String,      // Productization: "block_signup", "manual_review"
    pub profile: String,     // Productization: "bot_attacker", "legit_user"
    pub explanation: std::collections::HashMap<String, u8>, // Productization: Factor weighting
    pub recommendation: String,
    pub signals: Signals,
    pub network: NetworkContext,
    pub location: LocationContext,
    pub behavior: BehaviorContext,
    pub threats: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signals {
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_tor: bool,
    pub is_datacenter: bool,
    pub is_known_attacker: bool,
    pub is_honeypot_caught: bool,
    pub is_community_reported: bool,
    pub is_high_velocity: bool, // Sentinel addition
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkContext {
    pub asn: String,
    pub isp: String,
    pub r#type: String,
    pub asn_score: u8,       // Sentinel addition
    pub stability_rank: String, // Sentinel addition
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LocationContext {
    pub country: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub geo_risk_score: u8, // Sentinel addition
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BehaviorContext {
    pub recent_reports: u32,
    pub first_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_attack: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IpPath {
    pub ip: String,
}

#[derive(Debug, Deserialize)]
pub struct ReportPayload {
    pub ip: String,
    pub source: String,
}

// --- Auth & Quota Models ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiKeyInfo {
    pub key: String,
    pub plan: String,
    pub daily_limit: i64,
    pub used_today: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
    pub upgrade_url: String,
}

// --- Phase 7: Admin, Blog & Stats Models ---

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub ip: String,
    pub action: String,
    pub profile: String,
    pub api_key: String,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct BlogPost {
    pub id: Option<i64>,
    pub title: String,
    pub slug: String,
    pub content: String,
    pub excerpt: String,
    pub author: String,
    pub category: String,
    pub published_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminStats {
    pub total_requests_24h: i64,
    pub top_ips: Vec<TopItem>,
    pub top_keys: Vec<TopItem>,
    pub geo_distribution: Vec<GeoPoint>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TopItem {
    pub label: String,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
    pub count: i64,
    pub country: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookConfig {
    pub api_key: String,
    pub url: String,
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct AdminAuthPayload {
    pub secret: String,
}
