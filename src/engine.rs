use crate::models::*;
use maxminddb::Reader;
use std::net::IpAddr;
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use std::time::{Duration, Instant};
use arc_swap::ArcSwap;
use ip_network_table::IpNetworkTable;
use ip_network::IpNetwork;
use moka::sync::Cache;
use chrono::{Utc, DateTime};
use dashmap::DashMap;
use once_cell::sync::Lazy;

// --- Static Intelligence Matrices ---

// Sentinel: ASN Reputation Database (Hardened)
static ASN_REPUTATION: Lazy<HashMap<u32, u8>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(4134, 80);  // High Spam ASN
    m.insert(4837, 75);  // High Attack ASN
    m.insert(16509, 30); // AWS (High VPN/Bot presence)
    m.insert(20473, 40); // Vultr (High Proxy presence)
    m.insert(14061, 35); // DigitalOcean
    m
});

// Sentinel: Geographic Risk Matrix (ISO-based)
static GEO_RISK: Lazy<HashMap<String, u8>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("CN".to_string(), 70);
    m.insert("RU".to_string(), 75);
    m.insert("KP".to_string(), 95);
    m.insert("IR".to_string(), 60);
    m.insert("UA".to_string(), 40);
    m
});

// Flags defined in compiler.rs
pub const FLAG_TOR: u8 = 1 << 0;
pub const FLAG_VPN: u8 = 1 << 1;
pub const FLAG_KNOWN_ATTACKER: u8 = 1 << 3;
pub const FLAG_HONEYPOT: u8 = 1 << 4;
pub const FLAG_COMMUNITY: u8 = 1 << 5;

#[derive(Clone, Debug)]
pub struct IpHistory {
    pub first_seen: DateTime<Utc>,
    pub recent_reports: u32,
    pub last_seen_attack: Option<DateTime<Utc>>,
}

/// The Sentinel Decision Engine
/// High-density intelligence core for Riskora
pub struct DecisionEngine {
    pub reader_city: Reader<Vec<u8>>,
    pub reader_asn: Reader<Vec<u8>>,
    pub datacenters: HashSet<u32>,
    pub threat_table: Arc<ArcSwap<IpNetworkTable<u8>>>,
    pub behavior_cache: Cache<String, IpHistory>,
    pub velocity_store: DashMap<String, (u32, Instant)>, // (Count, LastUpdate)
}

impl DecisionEngine {
    /// Initialize the Sentinel Core with all intelligence datasets
    pub fn new() -> Self {
        println!("🏛️  Initializing Riskora SENTINEL CORE (High-Density Logic)...");
        
        let reader_city = Reader::open_readfile("data/dbip.mmdb").expect("CRITICAL: City MMDB missing");
        let reader_asn = Reader::open_readfile("data/dbip-asn.mmdb").expect("CRITICAL: ASN MMDB missing");
        
        let dc_data = std::fs::read("data/datacenters.bin").unwrap_or_default();
        let datacenters: HashSet<u32> = bincode::deserialize(&dc_data).unwrap_or_default();

        let threats = Self::load_threats();
        
        let behavior_cache = Cache::builder()
            .max_capacity(1_000_000)
            .time_to_idle(Duration::from_secs(48 * 60 * 60))
            .build();

        let velocity_store = DashMap::new();

        println!("✅ SENTINEL CORE BOOTED. Ready for high-traffic intelligence autopsy.");

        Self {
            reader_city,
            reader_asn,
            datacenters,
            threat_table: Arc::new(ArcSwap::from_pointee(threats)),
            behavior_cache,
            velocity_store,
        }
    }

    /// Load the 4-Tier OSINT threat matrix into the RAM table
    fn load_threats() -> IpNetworkTable<u8> {
        let mut table = IpNetworkTable::new();
        if let Ok(data) = std::fs::read("data/threats.bin") {
            if let Ok(rules) = bincode::deserialize::<Vec<(IpNetwork, u8)>>(&data) {
                for (net, flag) in rules {
                    let existing = table.exact_match(net).copied().unwrap_or(0);
                    table.insert(net, existing | flag);
                }
                let (v4, v6) = table.len();
                println!("🛡️  Sentinel: Loaded {} global threat rules (IPv4: {}, IPv6: {}).", v4 + v6, v4, v6);
            }
        }
        table
    }

    /// Perform a full behavior and intelligence autopsy on a target IP
    pub fn evaluate(&self, ip_str: &str, context: &str) -> PremiumResponse {
        let ip: IpAddr = ip_str.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
        
        // --- LAYER 1: Intelligence Retrieval ---
        let city_res: Option<maxminddb::geoip2::City> = self.reader_city.lookup(ip).ok();
        let asn_res: Option<maxminddb::geoip2::Asn> = self.reader_asn.lookup(ip).ok();

        let country_iso = city_res.as_ref()
            .and_then(|c| c.country.as_ref())
            .and_then(|co| co.iso_code)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let city_name = city_res.as_ref()
            .and_then(|c| c.city.as_ref())
            .and_then(|ci| ci.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        
        let latitude = city_res.as_ref()
            .and_then(|c| c.location.as_ref())
            .and_then(|l| l.latitude)
            .unwrap_or(0.0);

        let longitude = city_res.as_ref()
            .and_then(|c| c.location.as_ref())
            .and_then(|l| l.longitude)
            .unwrap_or(0.0);
        
        let asn_num = asn_res.as_ref().and_then(|a| a.autonomous_system_number).unwrap_or(0);
        let org_str = asn_res.as_ref().and_then(|a| a.autonomous_system_organization).unwrap_or("Unknown");
        let isp_name = org_str.to_string();
        
        // 💡 لمسة الـ Senior: كشف الداتاسنتر تلقائياً من اسم الشركة!
        let org_lower = org_str.to_lowercase();
        let is_dc_by_name = org_lower.contains("cloudflare") || 
                            org_lower.contains("amazon") || 
                            org_lower.contains("digitalocean") ||
                            org_lower.contains("hetzner") ||
                            org_lower.contains("oracle");

        // --- LAYER 2: Behavioral & Infrastructure Analysis ---
        let is_datacenter = self.datacenters.contains(&asn_num) || is_dc_by_name;
        let threat_flags = self.threat_table.load().longest_match(ip).map(|(_, &f)| f).unwrap_or(0);
        let velocity_rank = self.track_velocity(ip_str);

        let behavior = self.behavior_cache.get(ip_str).unwrap_or_else(|| IpHistory {
            first_seen: Utc::now(),
            recent_reports: 0,
            last_seen_attack: None,
        });

        // --- LAYER 3: The SENTINEL Scoring Heuristics ---
        let mut base_score: i32 = 0;
        
        // A. Static Threat Lookups
        if (threat_flags & FLAG_TOR) != 0 { base_score += 100; }
        if (threat_flags & FLAG_HONEYPOT) != 0 { base_score += 120; }
        if (threat_flags & FLAG_KNOWN_ATTACKER) != 0 { base_score += 90; }
        
        // B. Infrastructure Reputation
        if is_datacenter { base_score += 30; }
        let asn_penalty = ASN_REPUTATION.get(&asn_num).copied().unwrap_or(0);
        base_score += asn_penalty as i32;

        // C. Geographic Risk Matrix
        let geo_penalty = GEO_RISK.get(&country_iso).copied().unwrap_or(5); // Default 5 points for any IP
        base_score += geo_penalty as i32;

        // D. Behavior & Velocity
        if velocity_rank > 10 { base_score += 45; } // Bot-like frequency
        if behavior.recent_reports > 0 { base_score += 65; }

        // Contextual Penalties
        if context == "payment" && (is_datacenter || (threat_flags & FLAG_VPN) != 0) {
            base_score += 40; 
        }

        let final_risk_score = base_score.clamp(0, 100) as u8;

        // --- LAYER 4: Resolution & Response Construction ---
        PremiumResponse {
            ip: ip_str.to_string(),
            risk_score: final_risk_score,
            risk_level: self.resolve_risk_level(final_risk_score),
            decision: self.resolve_decision(final_risk_score, context),
            confidence: self.calculate_confidence(threat_flags),
            reason: self.generate_reason_report(threat_flags, is_datacenter, velocity_rank, &country_iso),
            action: self.resolve_auth_action(final_risk_score, context, is_datacenter, threat_flags),
            profile: self.resolve_identity_profile(threat_flags, is_datacenter, velocity_rank),
            explanation: self.generate_factor_explanation(threat_flags, is_datacenter, velocity_rank, geo_penalty),
            recommendation: self.generate_recommendation(final_risk_score, context),
            signals: Signals {
                is_vpn: (threat_flags & FLAG_VPN) != 0,
                is_proxy: (threat_flags & FLAG_VPN) != 0 || is_datacenter,
                is_tor: (threat_flags & FLAG_TOR) != 0,
                is_datacenter,
                is_known_attacker: (threat_flags & FLAG_KNOWN_ATTACKER) != 0,
                is_honeypot_caught: (threat_flags & FLAG_HONEYPOT) != 0,
                is_community_reported: (threat_flags & FLAG_COMMUNITY) != 0,
                is_high_velocity: velocity_rank > 10,
            },
            network: NetworkContext {
                asn: format!("AS{}", asn_num),
                isp: isp_name,
                r#type: if is_datacenter { "Hosting/Infra".to_string() } else { "Consumer/ISP".to_string() },
                asn_score: 100 - asn_penalty,
                stability_rank: if velocity_rank > 20 { "VOLATILE" } else { "STABLE" }.to_string(),
            },
            location: LocationContext {
                country: country_iso,
                city: city_name,
                latitude,
                longitude,
                geo_risk_score: geo_penalty,
            },
            behavior: BehaviorContext {
                recent_reports: behavior.recent_reports,
                first_seen: behavior.first_seen.to_rfc3339(),
                last_seen_attack: behavior.last_seen_attack.map(|d| d.to_rfc3339()),
            },
            threats: self.compile_threat_list(threat_flags, is_datacenter, velocity_rank),
        }
    }

    /// Internal: Track and resolve IP request velocity in memory
    fn track_velocity(&self, ip: &str) -> u32 {
        let now = Instant::now();
        let mut velocity = self.velocity_store.entry(ip.to_string()).or_insert((0, now));
        
        // Reset every 60 seconds
        if now.duration_since(velocity.1).as_secs() > 60 {
            velocity.0 = 1;
            velocity.1 = now;
        } else {
            velocity.0 += 1;
        }
        
        velocity.0
    }

    fn resolve_risk_level(&self, score: u8) -> RiskLevel {
        if score > 80 { RiskLevel::High }
        else if score > 30 { RiskLevel::Medium }
        else { RiskLevel::Low }
    }

    fn resolve_decision(&self, score: u8, context: &str) -> Decision {
        match (score, context) {
            (86..=100, _) => Decision::Block,
            (61..=85, _) => Decision::Flag,
            (31..=60, _) => Decision::RequireCaptcha,
            _ => Decision::Allow,
        }
    }

    fn calculate_confidence(&self, flags: u8) -> u8 {
        if (flags & FLAG_HONEYPOT) != 0 { 100 }
        else if (flags & FLAG_TOR) != 0 { 99 }
        else if (flags & FLAG_KNOWN_ATTACKER) != 0 { 95 }
        else { 85 }
    }

    fn generate_reason_report(&self, flags: u8, is_dc: bool, velocity: u32, country: &str) -> String {
        let mut reasons = Vec::new();
        if (flags & FLAG_HONEYPOT) != 0 { reasons.push("VERIFIED_HONEYPOT_ATTACK"); }
        if (flags & FLAG_TOR) != 0 { reasons.push("ANONYMOUS_TOR_NODE"); }
        if (flags & FLAG_KNOWN_ATTACKER) != 0 { reasons.push("RBL_DATA_POSITIVE"); }
        if is_dc { reasons.push("INFRASTRUCTURE_IP"); }
        if velocity > 15 { reasons.push("ABNORMAL_VELOCITY_DETECTION"); }
        if GEO_RISK.contains_key(country) { reasons.push("GEOGRAPHIC_ANOMALY"); }

        if reasons.is_empty() { "Passive IP Signal Clean".to_string() }
        else { reasons.join(" || ") }
    }

    fn generate_recommendation(&self, score: u8, context: &str) -> String {
        match (score, context) {
            (86..=100, "signup") => "block_account_creation".to_string(),
            (86..=100, "payment") => "hard_decline_transaction".to_string(),
            (61..=85, "payment") => "manual_fraud_review_pending".to_string(),
            (31..=60, _) => "enforce_secondary_verification".to_string(),
            _ => "trust_and_proceed".to_string(),
        }
    }

    fn resolve_auth_action(&self, score: u8, context: &str, is_dc: bool, flags: u8) -> String {
        match (score, context) {
            (86..=100, "payment") => "BLOCK_TRANSACTION_AND_FLAG_CARD".to_string(),
            (86..=100, "signup") => "DENY_SIGNUP_AND_LOG_FINGERPRINT".to_string(),
            (61..=85, "payment") => "MANUAL_FRAUD_REVIEW_REQUIRED".to_string(),
            (61..=85, "signup") => "ENFORCE_HARD_CAPTCHA_AND_EMAIL_VERIFY".to_string(),
            (0..=30, _) => "ALLOW_PROCEED".to_string(),
            _ => {
                if is_dc || (flags & FLAG_VPN) != 0 { "REQUIRE_SECONDARY_AUTH".to_string() }
                else { "ALLOW_WITH_MONITORING".to_string() }
            }
        }
    }

    fn resolve_identity_profile(&self, flags: u8, is_dc: bool, velocity: u32) -> String {
        if (flags & FLAG_HONEYPOT) != 0 { "VERIFIED_THREAT_ACTOR".to_string() }
        else if velocity > 20 { "AGGRESSIVE_BOT_CRAWLER".to_string() }
        else if is_dc && (flags & FLAG_VPN) != 0 { "ANONYMOUS_PROXY_INFRA".to_string() }
        else if is_dc { "CLOUD_DATACENTER_NODE".to_string() }
        else if (flags & FLAG_VPN) != 0 { "RESIDENTIAL_PROXY_USER".to_string() }
        else { "ORGANIC_RESIDENTIAL_USER".to_string() }
    }

    fn generate_factor_explanation(&self, flags: u8, is_dc: bool, velocity: u32, geo: u8) -> HashMap<String, u8> {
        let mut m = HashMap::new();
        if (flags & FLAG_TOR) != 0 { m.insert("anonymity_network".to_string(), 35); }
        if (flags & FLAG_KNOWN_ATTACKER) != 0 { m.insert("osint_reputation".to_string(), 45); }
        if is_dc { m.insert("infrastructure_risk".to_string(), 20); }
        if velocity > 15 { m.insert("traffic_velocity".to_string(), 30); }
        m.insert("geographic_reliability".to_string(), geo);
        m
    }

    fn compile_threat_list(&self, flags: u8, is_dc: bool, velocity: u32) -> Vec<String> {
        let mut threats = Vec::new();
        if (flags & FLAG_TOR) != 0 { threats.push("tor_exit".to_string()); }
        if (flags & FLAG_KNOWN_ATTACKER) != 0 { threats.push("public_intelligence_match".to_string()); }
        if (flags & FLAG_HONEYPOT) != 0 { threats.push("active_honeypot_hit".to_string()); }
        if is_dc { threats.push("datacenter_origin".to_string()); }
        if velocity > 15 { threats.push("velocity_bot_signature".to_string()); }
        threats
    }
}
