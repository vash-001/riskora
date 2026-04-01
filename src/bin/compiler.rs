use ip_network::IpNetwork;
use reqwest;
use std::fs::File;
use std::io::Write;
use sqlx::{sqlite::SqliteConnectOptions, Connection, SqliteConnection, Row};

pub const FLAG_TOR: u8 = 1 << 0;
pub const FLAG_VPN: u8 = 1 << 1;
pub const FLAG_DATACENTER: u8 = 1 << 2;
pub const FLAG_KNOWN_ATTACKER: u8 = 1 << 3;
pub const FLAG_HONEYPOT: u8 = 1 << 4;
pub const FLAG_COMMUNITY: u8 = 1 << 5;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Riskora Data Compiler Started (4-Tier Thread Intel)...");
    
    let mut rules: Vec<(IpNetwork, u8)> = Vec::new();

    // 1. Fetch TOR Nodes
    println!("🔄 Fetching Tor Exit Nodes...");
    if let Ok(resp) = reqwest::get("https://check.torproject.org/torbulkexitlist").await {
        if let Ok(text) = resp.text().await {
            let mut count = 0;
            for line in text.lines() {
                if let Ok(ip) = line.parse::<std::net::IpAddr>() {
                    let prefix = if ip.is_ipv4() { 32 } else { 128 };
                    if let Ok(net) = IpNetwork::new(ip, prefix) {
                        rules.push((net, FLAG_TOR));
                        count += 1;
                    }
                }
            }
            println!("✅ Inserted {} Tor nodes.", count);
        }
    }

    // 2. Fetch Firehol Level 1 + Level 2 (OSINT)
    println!("🔄 Fetching Firehol Level 1 & 2 (OSINT CIDRs)...");
    let firehol_urls = vec![
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"
    ];
    for url in firehol_urls {
        if let Ok(resp) = reqwest::get(url).await {
            if let Ok(text) = resp.text().await {
                let mut count = 0;
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    
                    if let Ok(network) = line.parse::<IpNetwork>() {
                        rules.push((network, FLAG_KNOWN_ATTACKER));
                        count += 1;
                    }
                }
                println!("✅ Inserted {} OSINT Malicious CIDR blocks.", count);
            }
        }
    }

    // 3. Fetch Abuse.ch SSL Blacklist (Botnets)
    println!("🔄 Fetching Abuse.ch SSL Blacklist...");
    if let Ok(resp) = reqwest::get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv").await {
        if let Ok(text) = resp.text().await {
            let mut count = 0;
            for line in text.lines() {
                if line.starts_with('#') { continue; }
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() > 0 {
                    if let Ok(ip) = parts[0].parse::<std::net::IpAddr>() {
                        let prefix = if ip.is_ipv4() { 32 } else { 128 };
                        if let Ok(net) = IpNetwork::new(ip, prefix) {
                            rules.push((net, FLAG_KNOWN_ATTACKER));
                            count += 1;
                        }
                    }
                }
            }
            println!("✅ Inserted {} Botnet IPs.", count);
        }
    }

    // 4. THE MOAT: Read from Private `private_intel.db` Database (Honeypots & Client Feedback)
    println!("🔄 Connecting to Private SQLite Intelligence Moat...");
    let mut private_count = 0;
    
    let db_path = "data/private_intel.db";
    if std::path::Path::new(db_path).exists() {
        let mut conn = SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(db_path)).await?;
        let rows = sqlx::query("SELECT ip, source FROM reports")
            .fetch_all(&mut conn)
            .await?;
        
        for row in rows {
            let ip_str: String = row.get(0);
            let source: String = row.get(1);
            
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                if let Ok(net) = IpNetwork::new(ip, prefix) {
                    let flag = if source == "honeypot" { FLAG_HONEYPOT } else { FLAG_COMMUNITY };
                    rules.push((net, flag));
                    private_count += 1;
                }
            }
        }
        println!("✅ Injected {} High-Confidence Moat IPs.", private_count);
    }

    // 5. Datacenter ASN List (Infrastructure Intelligence)
    println!("🔄 Fetching Datacenter ASN Blacklist...");
    let mut dc_asns: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let dc_url = "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv";
    if let Ok(resp) = reqwest::get(dc_url).await {
        if let Ok(text) = resp.text().await {
            for line in text.lines() {
                if let Ok(asn) = line.trim().parse::<u32>() {
                    dc_asns.insert(asn);
                }
            }
            println!("✅ Loaded {} Cloud/Datacenter ASNs.", dc_asns.len());
        }
    }
    let dc_encoded: Vec<u8> = bincode::serialize(&dc_asns)?;
    let mut dc_file = File::create("data/datacenters.bin")?;
    dc_file.write_all(&dc_encoded)?;

    // Finalize
    println!("💾 Serializing flat IP Array...");
    let encoded: Vec<u8> = bincode::serialize(&rules)?;
    let mut file = File::create("data/threats.bin")?;
    file.write_all(&encoded)?;
    
    println!("🎉 Success! Saved {} entries ({} bytes) to 'data/threats.bin'", rules.len(), encoded.len());

    Ok(())
}
