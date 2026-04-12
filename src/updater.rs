use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use arc_swap::ArcSwap;
use ip_network_table::IpNetworkTable;
use ip_network::IpNetwork;
use crate::engine;

/// All live threat feed URLs to pull every 24 hours.
/// Each entry: (url, parse_mode)
/// parse_mode: "ip" = plain IPs, "cidr" = CIDR blocks, "ipsum" = IP+score pairs, "spamhaus" = CIDR with ; comments, "csv" = CSV where col0 is IP
const LIVE_FEEDS: &[(&str, &str)] = &[
    // High Priority
    ("https://check.torproject.org/torbulkexitlist",                                                                         "ip"),
    ("https://www.spamhaus.org/drop/drop.txt",                                                                               "spamhaus"),
    ("https://www.spamhaus.org/drop/edrop.txt",                                                                              "spamhaus"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",                             "cidr"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",                             "cidr"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",                             "cidr"),
    ("http://cinsscore.com/list/ci-badguys.txt",                                                                             "ip"),
    ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt",                                                              "ip"),
    ("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",                                                                  "csv"),
    // Medium Priority
    ("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",                                                    "ipsum"),
    ("https://www.botvrij.eu/data/ioc-ip.txt",                                                                               "ip"),
    ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt",                                                     "ip"),
    ("https://www.binarydefense.com/banlist.txt",                                                                            "ip"),
    ("https://lists.blocklist.de/lists/all.txt",                                                                             "ip"),
];

/// Starts a background task that refreshes the in-memory threat table every 24 hours.
pub fn start_threat_updater(threat_table: Arc<ArcSwap<IpNetworkTable<u8>>>) {
    tokio::spawn(async move {
        // First update 12 hours after boot (server already loaded threats.bin on startup)
        sleep(Duration::from_secs(12 * 3600)).await;

        loop {
            println!("🔄 [Auto-Updater] Starting 24h threat intelligence refresh cycle...");

            let mut new_table = IpNetworkTable::new();
            let mut total_new = 0usize;

            // Seed with existing static threats.bin first
            if let Ok(data) = std::fs::read("data/threats.bin") {
                if let Ok(rules) = bincode::deserialize::<Vec<(IpNetwork, u8)>>(&data) {
                    for (net, flag) in rules {
                        let existing = new_table.exact_match(net).copied().unwrap_or(0);
                        new_table.insert(net, existing | flag);
                    }
                }
            }

            // Pull every live feed
            for (url, mode) in LIVE_FEEDS {
                match reqwest::get(*url).await {
                    Ok(resp) => {
                        if let Ok(text) = resp.text().await {
                            let inserted = parse_feed(&mut new_table, &text, mode);
                            println!("  ✅ [{}] {} entries loaded", url.split('/').last().unwrap_or(url), inserted);
                            total_new += inserted;
                        }
                    }
                    Err(e) => {
                        eprintln!("  ⚠️ [Auto-Updater] Failed to fetch {}: {}", url, e);
                    }
                }
            }

            // Atomic swap — zero downtime, no requests dropped
            threat_table.store(Arc::new(new_table));
            println!("✅ [Auto-Updater] Complete. {} new threat entries loaded. Table swapped atomically.", total_new);

            sleep(Duration::from_secs(24 * 3600)).await;
        }
    });
}

/// Parses a feed's text content into the table based on its format.
fn parse_feed(table: &mut IpNetworkTable<u8>, text: &str, mode: &str) -> usize {
    let flag = engine::FLAG_KNOWN_ATTACKER;
    let mut count = 0;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let maybe_net: Option<IpNetwork> = match mode {
            "ip" => {
                line.parse::<std::net::IpAddr>().ok().and_then(|ip| {
                    let prefix = if ip.is_ipv4() { 32 } else { 128 };
                    IpNetwork::new(ip, prefix).ok()
                })
            }
            "cidr" => line.parse::<IpNetwork>().ok(),
            "spamhaus" => {
                // "1.2.3.0/24 ; SBL12345"
                let cidr = line.split(';').next().unwrap_or("").trim();
                cidr.parse::<IpNetwork>().ok()
            }
            "csv" => {
                // First column is IP
                let ip_str = line.split(',').next().unwrap_or("").trim();
                ip_str.parse::<std::net::IpAddr>().ok().and_then(|ip| {
                    let prefix = if ip.is_ipv4() { 32 } else { 128 };
                    IpNetwork::new(ip, prefix).ok()
                })
            }
            "ipsum" => {
                // "1.2.3.4\t7" — only include if score >= 3
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1].parse::<u32>().unwrap_or(0) >= 3 {
                    parts[0].parse::<std::net::IpAddr>().ok().and_then(|ip| {
                        let prefix = if ip.is_ipv4() { 32 } else { 128 };
                        IpNetwork::new(ip, prefix).ok()
                    })
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(net) = maybe_net {
            let existing = table.exact_match(net).copied().unwrap_or(0);
            table.insert(net, existing | flag);
            count += 1;
        }
    }

    count
}

