use crate::Result;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

fn parse_hex_key(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(format!("key hex must be 64 chars, got {}", s.len()).into());
    }
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex at byte {i}: {e}"))?;
    }
    Ok(k)
}

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
    pub userspace_only: bool,
}

/// XDP default policy for non-GUT traffic on the ingress NIC.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum XdpDefaultPolicy {
    /// Pass non-GUT packets to the kernel stack (XDP_PASS)
    Allow,
    /// Drop non-GUT packets at XDP level (XDP_DROP)
    Drop,
}

/// Obfuscation mode: how GUT packets appear on the wire.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ObfsMode {
    /// Packets look like QUIC (default).
    Quic,
    /// QUIC signatures masked — packets look like random UDP.
    Gost,
    /// Base64 Encoded with Syslog header pretending to be logs
    Syslog,
    /// Base64 Encoded with SIP header
    Sip,
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
    pub dynamic_peer: bool,
    pub responder: bool,
    pub ports: Vec<u16>,
    pub key: [u8; 32],
    pub keepalive_drop_percent: u8,
    pub outer_mtu: u16,
    pub own_http3: bool,
    pub wg_host: String,
    pub sip_domain: String,
    pub obfs: ObfsMode,
    pub bind_port: u16,
}

/// Global runtime settings (from config file [global] section or CLI).
#[derive(Clone)]
pub struct RuntimeConfig {
    pub stats_interval: u32,
    pub stat_file: String,
}

pub fn load_config(path: &str) -> Result<Config> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read config file '{path}': {e}"))?;
    parse_config(&content).map_err(|e| format!("Error in config file '{path}': {e}").into())
}

/// Build a [`Config`] entirely from environment variables — no file needed.
///
/// Required:
/// - `GUTD_PEER_IP`   — remote peer IP address (or `dynamic`)
/// - `GUTD_BIND_IP`  — local bind IP (use `0.0.0.0` for auto-detect)
/// - `GUTD_PORTS`    — comma-separated port list (e.g. `41000,41001,41002,41003`)
/// - `GUTD_KEY`      — 64-char hex key **or** `GUTD_PASSPHRASE` — plain-text passphrase
///
/// Optional (with defaults):
/// - `GUTD_ADDRESS`            — WireGuard tunnel address with prefix (e.g. `10.0.0.1/30`);
///   auto-generated if omitted
/// - `GUTD_RESPONDER`          — `true`/`false` override; inferred from address or dynamic_peer
/// - `GUTD_NAME`               — peer name              [default: `gut0`]
/// - `GUTD_MTU`                — inner MTU               [default: `1492`]
/// - `GUTD_OUTER_MTU`          — outer/physical MTU      [default: `1500`]
/// - `GUTD_NIC`                — ingress NIC override    [default: auto-detect]
/// - `GUTD_DEFAULT_POLICY`     — `allow` or `drop`       [default: `allow`]
/// - `GUTD_KEEPALIVE_DROP_PCT` — keepalive drop %        [default: `30`]
/// - `GUTD_OWN_HTTP3`          — `true`/`false`          [default: `true`]
/// - `GUTD_STATS_INTERVAL`     — stats interval seconds  [default: `5`]
/// - `GUTD_STAT_FILE`          — stat file path          [default: `/run/gutd.stat`]
pub fn load_config_from_env() -> Result<Config> {
    let getenv = |name: &str| -> Result<String> {
        std::env::var(name).map_err(|_| format!("Required env var {name} is not set").into())
    };

    let peer_ip_str = getenv("GUTD_PEER_IP")?;
    let (peer_ip, dynamic_peer) = if peer_ip_str.trim().eq_ignore_ascii_case("dynamic") {
        // Dynamic peer mode: server doesn't know peer IP in advance.
        // Use 0.0.0.0 as placeholder; BPF will learn the real endpoint.
        (IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), true)
    } else {
        let ip: IpAddr = peer_ip_str
            .parse()
            .map_err(|e| format!("GUTD_PEER_IP: invalid IP address: {e}"))?;
        (ip, false)
    };

    let bind_ip: IpAddr = std::env::var("GUTD_BIND_IP")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            s.parse()
                .map_err(|e| format!("GUTD_BIND_IP: invalid IP address: {e}"))
        })
        .transpose()?
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    let address_opt: Option<String> = std::env::var("GUTD_ADDRESS")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let responder_opt: Option<bool> = std::env::var("GUTD_RESPONDER")
        .ok()
        .map(|v| v == "true" || v == "1");

    // Resolve responder: explicit > address parity > dynamic_peer
    let responder = if let Some(r) = responder_opt {
        r
    } else if let Some(ref addr) = address_opt {
        let ip_part = addr.split('/').next().unwrap_or("");
        let parts: Vec<&str> = ip_part.split('.').collect();
        if parts.len() == 4 {
            parts[3].parse::<u8>().unwrap_or(0) & 1 == 1
        } else {
            false
        }
    } else {
        dynamic_peer
    };

    let address = address_opt.unwrap_or_else(|| {
        if responder {
            "10.47.0.1/30".to_string()
        } else {
            "10.47.0.2/30".to_string()
        }
    });

    let ports_str = getenv("GUTD_PORTS")?;
    let ports: Vec<u16> = ports_str
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u16>()
                .map_err(|e| format!("GUTD_PORTS: invalid port '{s}': {e}"))
        })
        .collect::<std::result::Result<_, _>>()?;
    if ports.is_empty() {
        return Err("GUTD_PORTS must not be empty".into());
    }
    for p in &ports {
        if *p == 0 {
            return Err("GUTD_PORTS: port 0 is not allowed".into());
        }
    }

    let key: [u8; 32] = if let Ok(hex) = std::env::var("GUTD_KEY")
        .or_else(|_| std::env::var("GUTD_SECRET"))
        .or_else(|_| std::env::var("GUTD_CIPHER"))
    {
        parse_hex_key(hex.trim()).map_err(|e| format!("GUTD_KEY: {e}"))?
    } else if let Ok(phrase) =
        std::env::var("GUTD_PASSPHRASE").or_else(|_| std::env::var("GUTD_PHRASE"))
    {
        let k = crate::crypto::derive_key(&phrase);
        eprintln!("Key derived from passphrase via HKDF-SHA256");
        k
    } else {
        return Err(
            "Either GUTD_KEY/GUTD_CIPHER (64-char hex) or GUTD_PASSPHRASE/GUTD_PHRASE must be set"
                .into(),
        );
    };

    let name = std::env::var("GUTD_NAME").unwrap_or_else(|_| "gut0".to_string());
    let mtu: u16 = std::env::var("GUTD_MTU")
        .unwrap_or_else(|_| "1492".to_string())
        .parse()
        .map_err(|e| format!("GUTD_MTU: {e}"))?;
    let userspace_only: bool = std::env::var("GUTD_USERSPACE_ONLY")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let outer_mtu: u16 = std::env::var("GUTD_OUTER_MTU")
        .unwrap_or_else(|_| "1500".to_string())
        .parse()
        .map_err(|e| format!("GUTD_OUTER_MTU: {e}"))?;
    let nic: Option<String> = std::env::var("GUTD_NIC")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let default_policy = match std::env::var("GUTD_DEFAULT_POLICY")
        .unwrap_or_else(|_| "allow".to_string())
        .as_str()
    {
        "allow" | "pass" => XdpDefaultPolicy::Allow,
        "drop" => XdpDefaultPolicy::Drop,
        other => {
            return Err(format!(
                "GUTD_DEFAULT_POLICY: unknown value '{other}', expected allow|drop"
            )
            .into())
        }
    };
    let keepalive_drop_percent: u8 = std::env::var("GUTD_KEEPALIVE_DROP_PCT")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .map_err(|e| format!("GUTD_KEEPALIVE_DROP_PCT: {e}"))?;
    let own_http3 = std::env::var("GUTD_OWN_HTTP3")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    let obfs = match std::env::var("GUTD_OBFS")
        .unwrap_or_else(|_| "quic".to_string())
        .as_str()
    {
        "quic" => ObfsMode::Quic,
        "gost" | "noise" => ObfsMode::Gost,
        "syslog" => ObfsMode::Syslog,
        "sip" => ObfsMode::Sip,
        other => {
            return Err(format!(
                "GUTD_OBFS: unknown value '{other}', expected quic|gost|noise|syslog|sip"
            )
            .into())
        }
    };
    let stats_interval: u32 = std::env::var("GUTD_STATS_INTERVAL")
        .unwrap_or_else(|_| "5".to_string())
        .parse()
        .map_err(|e| format!("GUTD_STATS_INTERVAL: {e}"))?;
    let stat_file =
        std::env::var("GUTD_STAT_FILE").unwrap_or_else(|_| "/run/gutd.stat".to_string());

    Ok(Config {
        global: GlobalConfig {
            outer_mtu,
            userspace_only,
        },
        runtime: RuntimeConfig {
            stats_interval,
            stat_file,
        },
        peers: vec![PeerConfig {
            name,
            mtu,
            nic,
            default_policy,
            address,
            bind_ip,
            peer_ip,
            dynamic_peer,
            responder,
            ports,
            key,
            keepalive_drop_percent,
            outer_mtu,
            own_http3,
            wg_host: std::env::var("GUTD_WG_HOST")
                .unwrap_or_else(|_| "127.0.0.1:51820".to_string()),
            sip_domain: std::env::var("GUTD_SNI")
                .or_else(|_| std::env::var("GUTD_SIP_DOMAIN"))
                .or_else(|_| std::env::var("GUTD_SERVICE_NAME"))
                .unwrap_or_else(|_| "nginx".to_string()),
            obfs,
            bind_port: std::env::var("GUTD_BIND_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }],
    })
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
    dynamic_peer: bool,
    responder: Option<bool>,
    ports: Option<Vec<u16>>,
    key: Option<[u8; 32]>,
    passphrase: Option<String>,
    keepalive_drop_percent: u8,
    own_http3: bool,
    wg_host: Option<String>,
    sip_domain: Option<String>,
    obfs: ObfsMode,
    bind_port: Option<u16>,
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
            dynamic_peer: false,
            responder: None,
            ports: None,
            key: None,
            passphrase: None,
            keepalive_drop_percent: 30,
            own_http3: true,
            wg_host: None,
            obfs: ObfsMode::Quic,
            sip_domain: None,
            bind_port: None,
        }
    }
}

impl PeerBuilder {
    fn build(self, outer_mtu: u16, peer_index: usize) -> Result<PeerConfig> {
        // Resolve responder role:
        //   1. Explicit `responder = true/false` wins
        //   2. If address is set, derive from last-octet parity (odd = responder)
        //   3. dynamic_peer implies responder (server side)
        //   4. Default: initiator (false)
        let responder = if let Some(r) = self.responder {
            r
        } else if let Some(ref addr) = self.address {
            let ip_part = addr.split('/').next().unwrap_or("");
            let parts: Vec<&str> = ip_part.split('.').collect();
            if parts.len() == 4 {
                parts[3].parse::<u8>().unwrap_or(0) & 1 == 1
            } else {
                false
            }
        } else {
            self.dynamic_peer
        };

        // Auto-generate veth address if not specified.
        // Each peer gets its own /30 block: 10.47.0.{idx*4+1}/30 or .{idx*4+2}/30
        let address = self.address.unwrap_or_else(|| {
            let base = peer_index * 4;
            if responder {
                format!("10.47.0.{}/30", base + 1)
            } else {
                format!("10.47.0.{}/30", base + 2)
            }
        });

        let bind_ip = self
            .bind_ip
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let peer_ip = if self.dynamic_peer {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            self.peer_ip.ok_or("peer_ip not set")?
        };
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
            dynamic_peer: self.dynamic_peer,
            responder,
            ports,
            key,
            keepalive_drop_percent: self.keepalive_drop_percent,
            outer_mtu,
            own_http3: self.own_http3,
            wg_host: self
                .wg_host
                .unwrap_or_else(|| "127.0.0.1:51820".to_string()),
            obfs: self.obfs,
            sip_domain: self.sip_domain.unwrap_or_else(|| "127.0.0.1".to_string()),
            bind_port: self.bind_port.unwrap_or(0),
        })
    }
}

// ── Config file parser ────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn parse_config(content: &str) -> Result<Config> {
    let mut outer_mtu = 1500u16;
    let mut userspace_only = false;
    let mut stats_interval = 5u32;
    let mut stat_file = "/run/gutd.stat".to_string();

    let mut peers: Vec<PeerConfig> = Vec::new();
    let mut current_builder: Option<PeerBuilder> = None;
    let mut current_section = "";

    let finalize_peer = |builder: PeerBuilder, outer_mtu: u16, idx: usize| -> Result<PeerConfig> {
        builder.build(outer_mtu, idx)
    };

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
                    let idx = peers.len();
                    peers.push(finalize_peer(builder, outer_mtu, idx)?);
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
                    "userspace_only" => userspace_only = value.parse()?,
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
                        "bind_port" => b.bind_port = Some(value.parse()?),
                        "peer_ip" => {
                            if value.eq_ignore_ascii_case("dynamic") {
                                b.dynamic_peer = true;
                            } else {
                                b.peer_ip = Some(value.parse()?);
                            }
                        }
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
                            b.key = Some(parse_hex_key(value.trim())?);
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
                        "wg_host" | "wg_port" => {
                            if key_name == "wg_port" {
                                b.wg_host = Some(format!("127.0.0.1:{}", value));
                            } else {
                                b.wg_host = Some(value.to_string());
                            }
                        }
                        "own_http3" => {
                            b.own_http3 = value == "true" || value == "1";
                        }
                        "responder" => {
                            b.responder = Some(value == "true" || value == "1");
                        }
                        "sip_domain" | "sni" | "service_name" => {
                            b.sip_domain = Some(value.trim_matches('"').to_string());
                        }
                        "obfs" => {
                            b.obfs = match value {
                                "quic" => ObfsMode::Quic,
                                "gost" | "noise" => ObfsMode::Gost,
                                "syslog" => ObfsMode::Syslog,
                                "sip" => ObfsMode::Sip,
                                _ => {
                                    return Err(format!(
                                        "Invalid obfs value: {value} (expected quic|gost|noise|syslog|sip)"
                                    )
                                    .into())
                                }
                            };
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
        let idx = peers.len();
        peers.push(finalize_peer(builder, outer_mtu, idx)?);
    }

    if peers.is_empty() {
        return Err("No [peer] sections found in config ".into());
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
        global: GlobalConfig {
            outer_mtu,
            userspace_only,
        },
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

    #[test]
    fn test_parse_config_dynamic_peer() {
        let content = r"
[global]
outer_mtu = 1500

[peer]
name = gut0
mtu = 1400
address = 10.0.0.1/30
bind_ip = 192.168.1.1
peer_ip = dynamic
ports = 41000,41001
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let config = parse_config(content).unwrap();
        assert!(config.peer().dynamic_peer);
        assert!(config.peer().responder); // 10.0.0.1 → odd → responder
        assert_eq!(
            config.peer().peer_ip,
            "0.0.0.0".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_responder_explicit_true() {
        let content = r"
[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = dynamic
ports = 41000
responder = true
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let config = parse_config(content).unwrap();
        assert!(config.peer().responder);
        assert_eq!(config.peer().address, "10.47.0.1/30");
    }

    #[test]
    fn test_responder_inferred_from_dynamic_peer() {
        let content = r"
[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = dynamic
ports = 41000
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let config = parse_config(content).unwrap();
        assert!(config.peer().responder);
        assert_eq!(config.peer().address, "10.47.0.1/30");
    }

    #[test]
    fn test_initiator_default_no_address() {
        let content = r"
[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
ports = 41000
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let config = parse_config(content).unwrap();
        assert!(!config.peer().responder);
        assert_eq!(config.peer().address, "10.47.0.2/30");
    }

    #[test]
    fn test_responder_from_address_parity() {
        let content = r"
[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
address = 10.0.0.1/30
ports = 41000
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let config = parse_config(content).unwrap();
        assert!(config.peer().responder); // .1 is odd
        assert_eq!(config.peer().address, "10.0.0.1/30");
    }
}
