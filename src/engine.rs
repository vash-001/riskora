use crate::models::*;
use maxminddb::Reader;
use lazy_static::lazy_static;
use std::net::IpAddr;
use moka::sync::Cache;
use chrono::{Utc, DateTime};
use std::time::Duration;
use arc_swap::ArcSwap;
use ip_network_table::IpNetworkTable;
use ip_network::IpNetwork;
use std::fs::File;
use std::io::Read;

#[derive(Clone, Debug)]
pub struct IpHistory {
    pub first_seen: DateTime<Utc>,
    pub recent_reports: u32,
    pub last_seen_attack: Option<DateTime<Utc>>,
}

lazy_static! {
    pub static ref THREAT_DB: ArcSwap<IpNetworkTable<u8>> = {
        let mut table = IpNetworkTable::new();
        if let Ok(mut file) = File::open("data/threats.bin") {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_ok() {
                if let Ok(rules) = bincode::deserialize::<Vec<(IpNetwork, u8)>>(&buffer) {
                    for (net, flag) in rules {
                        let existing = table.exact_match(net).copied().unwrap_or(0);
                        table.insert(net, existing | flag);
                    }
                    println!("🛡️ Threat Matrix DB successfully rebuilt inside RAM.");
                }
            }
        }
        ArcSwap::from_pointee(table)
    };

    pub static ref GEO_DB: Option<Reader<Vec<u8>>> = {
        let path = "data/dbip.mmdb";
        match Reader::open_readfile(path) {
            Ok(reader) => { Some(reader) },
            Err(_) => { None }
        }
    };

    pub static ref BEHAVIOR_CACHE: Cache<String, IpHistory> = Cache::builder()
        .max_capacity(1_000_000)
        .time_to_idle(Duration::from_secs(24 * 60 * 60))
        .build();
}

pub struct DecisionEngine;

impl DecisionEngine {
    pub fn calculate_risk_score(signals: &Signals, context_type: &str, history: &IpHistory) -> u8 {
        let mut score: i32 = 0;
        
        if signals.is_tor { score += 80; }
        if signals.is_vpn { score += 40; }
        if signals.is_proxy { score += 30; }
        if signals.is_datacenter { score += 20; }
        
        // 🎯 THE MOAT: Absolute Destruction against known attackers
        if signals.is_known_attacker { score += 100; }
        if signals.is_honeypot_caught { score += 120; }
        if signals.is_community_reported { score += 50; }

        if history.recent_reports > 0 { score += 60; } 
        
        if context_type == "signup" {
             if signals.is_vpn || signals.is_datacenter { score += 15; }
        } else if context_type == "payment" {
             if signals.is_proxy { score += 40; }
        }

        score.clamp(0, 100) as u8
    }

    pub fn get_decision_and_recommendation(
        score: u8, 
        context_type: &str,
        signals: &Signals
    ) -> (RiskLevel, Decision, String, String) {
        
        let (risk_level, decision) = match score {
            0..=20 => (RiskLevel::Low, Decision::Allow),
            21..=50 => (RiskLevel::Medium, Decision::Flag),
            51..=85 => (RiskLevel::High, Decision::RequireCaptcha),
            _ => (RiskLevel::High, Decision::Block),
        };

        let mut threat_reasons = Vec::new();
        if signals.is_tor { threat_reasons.push("TOR Network"); }
        if signals.is_vpn { threat_reasons.push("VPN Detected"); }
        if signals.is_datacenter { threat_reasons.push("Datacenter IP"); }
        if signals.is_known_attacker { threat_reasons.push("OSINT Blacklisted"); }
        
        // Detailed Moat Reporting
        if signals.is_honeypot_caught { threat_reasons.push("Honeypot Assailant"); }
        if signals.is_community_reported { threat_reasons.push("Community Flagged"); }

        let reason = if threat_reasons.is_empty() {
            "Clean IP profile".to_string()
        } else {
            threat_reasons.join(" + ")
        };

        let recommendation = match (decision, context_type) {
            (Decision::Allow, _) => "allow".to_string(),
            (Decision::RequireCaptcha, "signup") => "require_email_verification".to_string(),
            (Decision::RequireCaptcha, "payment") => "require_3ds_challenge".to_string(),
            (Decision::RequireCaptcha, "login") => "require_2fa".to_string(),
            (Decision::Flag, "payment") => "manual_fraud_review".to_string(),
            (Decision::Flag, _) => "monitor_velocity".to_string(),
            (Decision::Block, "signup") => "block_signup".to_string(),
            (Decision::Block, "payment") => "decline_transaction".to_string(),
            (Decision::Block, "login") => "block_login".to_string(),
            _ => "block".to_string(),
        };

        (risk_level, decision, reason, recommendation)
    }

    pub fn reload_data_pipeline() {
        let mut table = IpNetworkTable::new();
        if let Ok(mut file) = File::open("data/threats.bin") {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_ok() {
                if let Ok(rules) = bincode::deserialize::<Vec<(IpNetwork, u8)>>(&buffer) {
                    for (net, flag) in rules {
                        let existing = table.exact_match(net).copied().unwrap_or(0);
                        table.insert(net, existing | flag);
                    }
                    THREAT_DB.store(std::sync::Arc::new(table));
                    println!("🔄 The Moat: Engine Reloaded with Expanded Intelligence!");
                }
            }
        }
    }

    pub fn evaluate(ip: &str, context_type: &str) -> PremiumResponse {
        let parsed_ip: IpAddr = ip.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

        let threat_flags = THREAT_DB.load().longest_match(parsed_ip).map(|(_, &v)| v).unwrap_or(0);

        const FLAG_TOR: u8 = 1 << 0;
        const FLAG_VPN: u8 = 1 << 1;
        const FLAG_DATACENTER: u8 = 1 << 2;
        const FLAG_KNOWN_ATTACKER: u8 = 1 << 3;
        const FLAG_HONEYPOT: u8 = 1 << 4;
        const FLAG_COMMUNITY: u8 = 1 << 5;

        let signals = Signals {
            is_vpn: (threat_flags & FLAG_VPN) != 0,
            is_proxy: false, 
            is_tor: (threat_flags & FLAG_TOR) != 0,
            is_datacenter: (threat_flags & FLAG_DATACENTER) != 0,
            is_known_attacker: (threat_flags & FLAG_KNOWN_ATTACKER) != 0,
            is_honeypot_caught: (threat_flags & FLAG_HONEYPOT) != 0,
            is_community_reported: (threat_flags & FLAG_COMMUNITY) != 0,
        };

        let now = Utc::now();
        let mut history = BEHAVIOR_CACHE.get(ip).unwrap_or_else(|| IpHistory {
            first_seen: now,
            recent_reports: 0,
            last_seen_attack: None,
        });

        let risk_score = Self::calculate_risk_score(&signals, context_type, &history);
        let (risk_level, decision, reason, recommendation) = Self::get_decision_and_recommendation(risk_score, context_type, &signals);

        let mut threats = vec![];
        if signals.is_tor { threats.push("tor".to_string()); }
        if signals.is_vpn { threats.push("vpn".to_string()); }
        if signals.is_datacenter { threats.push("datacenter".to_string()); }
        if signals.is_known_attacker { threats.push("osint_attacker".to_string()); }
        if signals.is_honeypot_caught { threats.push("verified_honeypot_hacker".to_string()); }
        if signals.is_community_reported { threats.push("community_reported_abuse".to_string()); }

        let confidence = if signals.is_honeypot_caught { 100 } else if risk_score > 60 { 95 } else { 88 };

        if risk_score >= 80 {
            history.last_seen_attack = Some(now);
        }
        BEHAVIOR_CACHE.insert(ip.to_string(), history.clone());

        let (country_out, city_out, asn_out, isp_out) = match &*GEO_DB {
            Some(db) => {
                let city_res: Result<maxminddb::geoip2::City, _> = db.lookup(parsed_ip);
                match city_res {
                    Ok(city) => {
                        let cntry = city.country.and_then(|c| c.iso_code).unwrap_or("Unknown").to_string();
                        let cty = city.city.and_then(|c| c.names).and_then(|n| n.get("en").copied()).unwrap_or("Unknown").to_string();
                        
                        // ASN/ISP are typically NOT in the City database unless using a combined one.
                        // We will set them to Unknown for now or handle gracefully if available in traits.
                        let asn = "Unknown".to_string();
                        let isp = "Unknown".to_string();

                        (cntry, cty, asn, isp)
                    },
                    Err(_) => ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string()),
                }
            },
            None => {
                ("US".to_string(), "San Francisco".to_string(), "AS448".to_string(), "Example ISP".to_string())
            }
        };

        PremiumResponse {
            ip: ip.to_string(),
            risk_score,
            risk_level,
            decision,
            confidence,
            reason,
            recommendation,
            signals: signals.clone(),
            network: NetworkContext {
                asn: asn_out,
                isp: isp_out,
                r#type: if signals.is_datacenter { "datacenter".to_string() } else { "unknown".to_string() },
            },
            location: LocationContext {
                country: country_out,
                city: city_out,
            },
            behavior: BehaviorContext {
                recent_reports: history.recent_reports,
                first_seen: history.first_seen.to_rfc3339(),
                last_seen_attack: history.last_seen_attack.map(|d| d.to_rfc3339()),
            },
            threats,
        }
    }
}
