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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkContext {
    pub asn: String,
    pub isp: String,
    pub r#type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LocationContext {
    pub country: String,
    pub city: String,
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
