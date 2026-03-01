use crate::Result;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

#[derive(Clone)]
pub struct Config {
    pub global: GlobalConfig,
    pub runtime: RuntimeConfig,
    pub peers: Vec<PeerConfig>,
}

impl Config {
    /// Returns the first peer. Panics if `peers` is empty (impossible after
    /// successful `parse_config`). Keeps loader.rs call-sites terse.
    pub fn peer(&self) -> &PeerConfig {
        &self.peers[0]
    }
}

#[derive(Clone)]
pub struct GlobalConfig {
    pub outer_mtu: u16,
}

/// XDP default policy for non-GUT traffic on the ingress NIC.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum XdpDefaultPolicy {
    /// Pass non-GUT packets to the kernel stack (XDP_PASS)
    Allow,
    /// Drop non-GUT packets at XDP level (XDP_DROP)
    Drop,
}

#[derive(Clone)]
pub struct PeerConfig {
    pub name: String,
    pub mtu: u16,
    pub nic: Option<String>,
    pub default_policy: XdpDefaultPolicy,
    pub address: String,
    pub bind_ip: IpAddr,
    pub peer_ip: IpAddr,
    pub ports: Vec<u16>,
    pub key: [u8; 32],
    pub keepalive_drop_percent: u8,
    pub outer_mtu: u16,
}

/// Global runtime settings (from config file [global] section or CLI).
#[derive(Clone)]
pub struct RuntimeConfig {
    pub stats_interval: u32,
    pub stat_file: String,
}

pub fn load_config(path: &str) -> Result<Config> {
    let content = fs::read_to_string(path)?;
    parse_config(&content)
}

// ── Per-peer accumulator used while parsing ───────────────────────────────────

struct PeerBuilder {
    name: String,
    mtu: u16,
    nic: Option<String>,
    default_policy: XdpDefaultPolicy,
    address: Option<String>,
    bind_ip: Option<IpAddr>,
    peer_ip: Option<IpAddr>,
    ports: Option<Vec<u16>>,
    key: Option<[u8; 32]>,
    passphrase: Option<String>,
    keepalive_drop_percent: u8,
}

impl Default for PeerBuilder {
    fn default() -> Self {
        Self {
            name: "gut0".to_string(),
            mtu: 1492,
            nic: None,
            default_policy: XdpDefaultPolicy::Allow,
            address: None,
            bind_ip: None,
            peer_ip: None,
            ports: None,
            key: None,
            passphrase: None,
            keepalive_drop_percent: 75,
        }
    }
}

impl PeerBuilder {
    fn build(self, outer_mtu: u16) -> Result<PeerConfig> {
        let address = self
            .address
            .ok_or_else(|| format!("address not set in [peer] (name={})", self.name))?;
        let bind_ip = self.bind_ip.ok_or("bind_ip not set")?;
        let peer_ip = self.peer_ip.ok_or("peer_ip not set")?;
        let ports = self.ports.ok_or("ports not set")?;
        let key = match (self.key, self.passphrase) {
            (Some(k), _) => k,
            (None, Some(p)) => {
                let k = crate::crypto::derive_key(&p);
                eprintln!(
                    "Key derived from passphrase via HKDF-SHA256 (peer: {})",
                    self.name
                );
                k
            }
            (None, None) => {
                return Err(format!(
                    "Either key or passphrase must be set in [peer] (name={})",
                    self.name
                )
                .into())
            }
        };
        Ok(PeerConfig {
            name: self.name,
            mtu: self.mtu,
            nic: self.nic,
            default_policy: self.default_policy,
            address,
            bind_ip,
            peer_ip,
            ports,
            key,
            keepalive_drop_percent: self.keepalive_drop_percent,
            outer_mtu,
        })
    }
}

// ── Config file parser ────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn parse_config(content: &str) -> Result<Config> {
    let mut outer_mtu = 1500u16;
    let mut stats_interval = 5u32;
    let mut stat_file = "/run/gutd.stat".to_string();

    let mut peers: Vec<PeerConfig> = Vec::new();
    let mut current_builder: Option<PeerBuilder> = None;
    let mut current_section = "";

    let finalize_peer =
        |builder: PeerBuilder, outer_mtu: u16| -> Result<PeerConfig> { builder.build(outer_mtu) };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            if section == "peer" {
                // Finalize the previous [peer] block, if any.
                if let Some(builder) = current_builder.take() {
                    peers.push(finalize_peer(builder, outer_mtu)?);
                }
                current_builder = Some(PeerBuilder::default());
            }
            current_section = section;
            continue;
        }

        if let Some(eq_pos) = line.find('=') {
            let key_name = line[..eq_pos].trim();
            let raw_value = line[eq_pos + 1..].trim();
            let value = if let Some(stripped) = raw_value.strip_prefix('"') {
                match stripped.find('"') {
                    Some(end) => &raw_value[..end + 2],
                    None => raw_value,
                }
            } else {
                match raw_value.find('#') {
                    Some(hash_pos) => raw_value[..hash_pos].trim(),
                    None => raw_value,
                }
            };

            match current_section {
                "global" => match key_name {
                    "outer_mtu" => outer_mtu = value.parse()?,
                    "stats_interval" => stats_interval = value.parse()?,
                    "stat_file" => stat_file = value.trim_matches('"').to_string(),
                    _ => {}
                },
                "peer" => {
                    let b = current_builder.get_or_insert_with(PeerBuilder::default);
                    match key_name {
                        "name" => b.name = value.to_string(),
                        "mtu" => b.mtu = value.parse()?,
                        "nic" => b.nic = Some(value.to_string()),
                        "address" => b.address = Some(value.to_string()),
                        "default_policy" => {
                            b.default_policy = match value {
                                "allow" | "pass" => XdpDefaultPolicy::Allow,
                                "drop" => XdpDefaultPolicy::Drop,
                                _ => {
                                    return Err(format!(
                                        "Invalid default_policy: {value} (expected allow|drop)"
                                    )
                                    .into())
                                }
                            };
                        }
                        "bind_ip" => b.bind_ip = Some(value.parse()?),
                        "peer_ip" => b.peer_ip = Some(value.parse()?),
                        "ports" => {
                            let parsed: Result<Vec<u16>> = value
                                .split(',')
                                .map(|s| {
                                    s.trim()
                                        .parse()
                                        .map_err(|e| format!("Port parse error: {e}").into())
                                })
                                .collect();
                            let parsed = parsed?;
                            if parsed.is_empty() {
                                return Err("ports must not be empty".into());
                            }
                            for port in &parsed {
                                if *port == 0 {
                                    return Err("ports must be in range 1..65535".into());
                                }
                            }
                            b.ports = Some(parsed);
                        }
                        "key" => {
                            let hex_str = value.trim();
                            if hex_str.len() != 64 {
                                return Err(format!(
                                    "Key must be 64 hex chars, got {}",
                                    hex_str.len()
                                )
                                .into());
                            }
                            let mut key_bytes = [0u8; 32];
                            for i in 0..32 {
                                key_bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)?;
                            }
                            b.key = Some(key_bytes);
                        }
                        "passphrase" => {
                            b.passphrase = Some(value.trim_matches('"').to_string());
                        }
                        "keepalive_drop_percent" => {
                            let parsed: u8 = value.parse()?;
                            if parsed > 100 {
                                return Err("keepalive_drop_percent must be in range 0..100".into());
                            }
                            b.keepalive_drop_percent = parsed;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    // Finalize last [peer] block.
    if let Some(builder) = current_builder.take() {
        peers.push(finalize_peer(builder, outer_mtu)?);
    }

    if peers.is_empty() {
        return Err("No [peer] sections found in config".into());
    }

    // Validate: peer names must be unique.
    let mut seen_names: HashSet<&str> = HashSet::new();
    for p in &peers {
        if !seen_names.insert(p.name.as_str()) {
            return Err(format!("Duplicate peer name: '{}'", p.name).into());
        }
    }

    // Validate: no port may appear in more than one peer's port list.
    // Duplicates within a single peer's list are fine (port striping).
    let mut seen_ports: HashSet<u16> = HashSet::new();
    for p in &peers {
        let unique: HashSet<u16> = p.ports.iter().copied().collect();
        for port in unique {
            if !seen_ports.insert(port) {
                return Err(format!(
                    "Port {} is used by multiple peers — each port must belong to exactly one peer",
                    port
                )
                .into());
            }
        }
    }

    Ok(Config {
        global: GlobalConfig { outer_mtu },
        runtime: RuntimeConfig {
            stats_interval,
            stat_file,
        },
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let content = r"
[global]
outer_mtu = 1500

[peer]
name = gut0
mtu = 1400
address = 10.0.0.1/30
bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
ports = 41000,41001,41002,41003
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let config = parse_config(content).unwrap();
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peer().ports.len(), 4);
        assert_eq!(config.peer().name, "gut0");
    }

    #[test]
    fn test_parse_config_multi_peer() {
        let content = r"
[global]
outer_mtu = 1500

[peer]
name = gut0
mtu = 1400
address = 10.0.0.1/30
bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
ports = 41000,41001
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

[peer]
name = gut1
mtu = 1400
address = 10.0.0.5/30
bind_ip = 0.0.0.0
peer_ip = 203.0.113.11
ports = 41002,41003
key = ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
";
        let config = parse_config(content).unwrap();
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers[0].name, "gut0");
        assert_eq!(config.peers[1].name, "gut1");
        assert_eq!(config.peers[0].ports, vec![41000, 41001]);
        assert_eq!(config.peers[1].ports, vec![41002, 41003]);
    }

    #[test]
    fn test_parse_config_allows_duplicate_ports_within_peer() {
        let content = r"
[global]
outer_mtu = 1500

[peer]
name = gut0
mtu = 1400
address = 10.0.0.1/30
bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
ports = 41000,41001,41000
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let config = parse_config(content).unwrap();
        assert_eq!(config.peer().ports, vec![41000, 41001, 41000]);
    }

    #[test]
    fn test_parse_config_rejects_duplicate_ports_across_peers() {
        let content = r"
[global]
outer_mtu = 1500

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
ports = 41000,41001
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

[peer]
name = gut1
bind_ip = 0.0.0.0
peer_ip = 203.0.113.11
ports = 41001,41002
key = ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
";
        assert!(parse_config(content).is_err());
    }

    #[test]
    fn test_parse_config_rejects_duplicate_peer_names() {
        let content = r"
[global]
outer_mtu = 1500

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
ports = 41000
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 203.0.113.11
ports = 41001
key = ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
";
        assert!(parse_config(content).is_err());
    }
}
