//! Authorized LAN scanning: host discovery (`netscan`) and TCP port scanning
//! (`portscan`).
//!
//! Everything here is TCP-connect based — no raw sockets, no root, works on
//! all three platforms. Scan actions are gated behind an explicit permission
//! acknowledgement (CLI flag or `NETON_I_HAVE_PERMISSION=yes`); over the
//! BIT Remote API the server itself must be started with that acknowledgement
//! or the actions answer HTTP 403.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::models::{Device, NetScanResult, OpenPort, PortScanResult};

/// Hard cap of hosts in one scan (home use: /20 is already generous).
pub const MAX_SCAN_HOSTS: u32 = 4096;
/// Hard cap of ports per scan.
pub const MAX_SCAN_PORTS: usize = 4096;
/// Hard cap of scan concurrency.
pub const MAX_SCAN_CONCURRENCY: usize = 256;
/// Actions that require the scan permission acknowledgement.
pub const SCAN_ACTIONS: [&str; 3] = ["netscan", "portscan", "device"];

/// Default discovery ports used by `netscan`.
pub const DEFAULT_NETSCAN_PORTS: [u16; 6] = [22, 80, 443, 445, 3389, 8080];
/// Default concurrency for `netscan`.
pub const DEFAULT_NETSCAN_CONCURRENCY: u64 = 128;
/// Default connect timeout (ms) for `netscan`.
pub const DEFAULT_NETSCAN_TIMEOUT_MS: u64 = 400;
/// Default concurrency for `portscan`.
pub const DEFAULT_PORTSCAN_CONCURRENCY: u64 = 200;
/// Default connect timeout (ms) for `portscan`.
pub const DEFAULT_PORTSCAN_TIMEOUT_MS: u64 = 800;

/// Top ports probed by the `common` preset.
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 443, 445, 554, 587, 993, 995, 1433, 1900, 2375,
    3306, 3389, 5000, 5432, 5555, 6379, 7531, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9100,
    49152, 50050, 50051,
];

/// Well-known service names for the most common ports.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 | 445 => "smb",
        143 => "imap",
        443 => "https",
        554 => "rtsp",
        587 => "smtp-submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1900 => "ssdp",
        2375 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5000 | 8443 => "https-alt",
        5432 => "postgres",
        5555 => "adb",
        6379 => "redis",
        7531 => "synology-dsm",
        9100 => "printer",
        50050 | 50051 => "grpc",
        _ => return None,
    })
}

// ------------------------------------------------------------ permission ----

/// Error type for a missing scan permission acknowledgement (exit code 2).
#[derive(Debug)]
pub struct PermissionRequired {
    pub action: String,
}

impl std::fmt::Display for PermissionRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "action '{}' is a network scan and requires explicit authorization: re-run with \
             --yes-i-have-permission, or set NETON_I_HAVE_PERMISSION=yes. Only scan networks you \
             own or are authorized to test.",
            self.action
        )
    }
}

impl std::error::Error for PermissionRequired {}

/// True when the scan permission was acknowledged via env var.
pub fn permission_via_env() -> bool {
    std::env::var("NETON_I_HAVE_PERMISSION")
        .map(|value| value.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

/// Ensure a scan action is authorized (CLI path; exits with code 2 when not).
pub fn ensure_scan_permission(action: &str, authorized: bool) -> Result<()> {
    if authorized {
        return Ok(());
    }
    Err(anyhow::Error::new(PermissionRequired {
        action: action.to_string(),
    }))
}

// ------------------------------------------------------------------ cidr ----

/// Parse an IPv4 CIDR (`192.168.1.0/24`) or a bare IP (treated as /32).
/// Host bits, when set, are normalized to the network address.
pub fn parse_cidr(input: &str) -> Result<(Ipv4Addr, u8)> {
    let input = input.trim();
    let (addr_part, prefix_part) = match input.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (input, None),
    };
    let addr: Ipv4Addr = addr_part
        .parse()
        .with_context(|| format!("invalid IPv4 address in '{input}'"))?;
    let prefix: u8 = match prefix_part {
        None => 32,
        Some(p) => p
            .parse()
            .with_context(|| format!("invalid prefix length in '{input}'"))?,
    };
    if prefix > 32 {
        bail!("prefix length in '{input}' must be <= 32");
    }
    let network = normalize_network(addr, prefix);
    Ok((network, prefix))
}

/// Mask off host bits to get the network address.
pub fn normalize_network(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let raw = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    Ipv4Addr::from(raw & mask)
}

/// Enumerate all host addresses of a CIDR (network + broadcast included for
/// /31 and /32 semantics; rejected earlier for oversized prefixes).
pub fn cidr_hosts(network: Ipv4Addr, prefix: u8) -> Result<Vec<Ipv4Addr>> {
    let host_bits = 32 - prefix as u32;
    let total = 2u64
        .checked_pow(host_bits)
        .ok_or_else(|| anyhow!("CIDR too large"))?;
    if total > MAX_SCAN_HOSTS as u64 {
        bail!(
            "CIDR contains {total} hosts; the limit is {} (use a smaller prefix)",
            MAX_SCAN_HOSTS
        );
    }
    let base = u32::from(network);
    Ok((0..total)
        .map(|i| Ipv4Addr::from(base + i as u32))
        .collect())
}

// ------------------------------------------------------------ port specs ----

/// Parse a port specification: `common`, `all-mentioned` list like
/// `80,443,8000-8100`, or a range `1-1024`. Duplicates removed, sorted.
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("common") {
        return Ok(COMMON_PORTS.to_vec());
    }
    let mut ports = std::collections::BTreeSet::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((from, to)) = part.split_once('-') {
            let from: u16 = from
                .parse()
                .with_context(|| format!("invalid port range '{part}'"))?;
            let to: u16 = to
                .parse()
                .with_context(|| format!("invalid port range '{part}'"))?;
            if from == 0 || to < from || to - from > MAX_SCAN_PORTS as u16 {
                bail!("invalid port range '{part}' (max span is {MAX_SCAN_PORTS})");
            }
            for port in from..=to {
                ports.insert(port);
            }
        } else {
            let port: u16 = part
                .parse()
                .with_context(|| format!("invalid port '{part}'"))?;
            if port == 0 {
                bail!("port 0 is not scannable");
            }
            ports.insert(port);
        }
        if ports.len() > MAX_SCAN_PORTS {
            bail!("more than {MAX_SCAN_PORTS} ports requested");
        }
    }
    if ports.is_empty() {
        bail!("empty port specification");
    }
    Ok(ports.into_iter().collect())
}

// ----------------------------------------------------------------- sweep ----

/// One TCP connect probe with timeout. True when the connection succeeded.
pub fn tcp_probe(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::new(ip, port);
    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
}

/// One successful TCP connect.
#[derive(Debug, Clone)]
pub struct SweepHit {
    pub ip: IpAddr,
    pub port: u16,
    pub elapsed_ms: u64,
}

/// Concurrently TCP-connect every (ip, port) pair with a bounded thread pool
/// and return the successful ones (in completion order).
pub fn sweep(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout_ms: u64,
) -> Vec<SweepHit> {
    let timeout_ms = timeout_ms.clamp(1, 60_000);
    let pairs = hosts.len().saturating_mul(ports.len());
    if pairs == 0 {
        return Vec::new();
    }
    let concurrency = concurrency.clamp(1, MAX_SCAN_CONCURRENCY).min(pairs);
    let hosts = Arc::new(hosts.to_vec());
    let ports = Arc::new(ports.to_vec());
    let next = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<SweepHit>();

    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let tx = tx.clone();
        let hosts = Arc::clone(&hosts);
        let ports = Arc::clone(&ports);
        let next = Arc::clone(&next);
        workers.push(std::thread::spawn(move || loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            if index >= pairs {
                break;
            }
            let host = hosts[index / ports.len()];
            let port = ports[index % ports.len()];
            let start = Instant::now();
            if tcp_probe(host, port, timeout_ms) {
                let hit = SweepHit {
                    ip: host,
                    port,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
                if tx.send(hit).is_err() {
                    break;
                }
            }
        }));
    }
    drop(tx);
    let results: Vec<SweepHit> = rx.into_iter().collect();
    for worker in workers {
        let _ = worker.join();
    }
    results
}

// --------------------------------------------------------------- netscan ----

/// Discover live devices in a subnet: concurrent TCP sweep over the given
/// discovery ports, then correlate with the system ARP table so devices
/// without any of the probed ports still show up (via `via: ["arp"]`).
pub fn netscan(
    cidr: &str,
    ports: &[u16],
    concurrency: usize,
    timeout_ms: u64,
    rdns: bool,
) -> Result<NetScanResult> {
    let (network, prefix) = parse_cidr(cidr)?;
    let hosts: Vec<IpAddr> = cidr_hosts(network, prefix)?
        .into_iter()
        .map(IpAddr::V4)
        .collect();
    let hosts_total = hosts.len();
    let start = Instant::now();

    // Pass 1: TCP sweep — every answering host is alive.
    let mut open_by_host: BTreeMap<IpAddr, Vec<OpenPort>> = BTreeMap::new();
    for hit in sweep(&hosts, ports, concurrency, timeout_ms) {
        let entry = open_by_host.entry(hit.ip).or_default();
        entry.push(OpenPort {
            port: hit.port,
            service: service_name(hit.port).map(str::to_string),
            elapsed_ms: hit.elapsed_ms,
        });
    }
    for entry in open_by_host.values_mut() {
        entry.sort_by_key(|p| p.port);
    }

    // Pass 2: ARP correlation within the scanned range.
    let arp_entries = crate::arp::read_arp_table().unwrap_or_default();
    let mut devices: Vec<Device> = Vec::new();
    let mut alive: Vec<IpAddr> = open_by_host.keys().copied().collect();
    for entry in &arp_entries {
        let in_range = match (entry.ip, network, prefix) {
            (IpAddr::V4(ip), net, p) => {
                let raw = u32::from(ip);
                let base = u32::from(net);
                let mask = if p == 0 {
                    0
                } else {
                    u32::MAX << (32 - p as u32)
                };
                raw & mask == base & mask
            }
            _ => false,
        };
        if in_range && !alive.contains(&entry.ip) {
            alive.push(entry.ip);
        }
    }
    alive.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) => u32::from(*v4),
        IpAddr::V6(_) => u32::MAX, // keep IPv6 entries last, rare in LAN scans
    });

    for ip in &alive {
        let open_ports = open_by_host.remove(ip).unwrap_or_default();
        let arp = arp_entries.iter().find(|entry| &entry.ip == ip);
        let mac = arp.and_then(|entry| entry.mac.clone());
        let vendor = arp.and_then(|entry| entry.vendor.clone());
        let mut via = Vec::new();
        if !open_ports.is_empty() {
            via.push("tcp".to_string());
        }
        if arp.is_some() {
            via.push("arp".to_string());
        }
        let hostname = if rdns { rdns_lookup(ip) } else { None };
        devices.push(Device {
            ip: *ip,
            mac,
            vendor,
            hostname,
            open_ports,
            via,
        });
    }

    Ok(NetScanResult {
        cidr: format!("{network}/{prefix}"),
        hosts_total,
        ports_probed: ports.to_vec(),
        concurrency,
        timeout_ms,
        devices_found: devices.len(),
        devices,
        arp_entries_seen: arp_entries.len(),
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Best-effort reverse DNS: ask the system's first resolver for a PTR record.
pub fn rdns_lookup(ip: &IpAddr) -> Option<String> {
    let server = system_dns_server()?;
    crate::dns_ptr::resolve_ptr(ip, server, Duration::from_millis(1000))
}

/// First system DNS resolver: parsed from `/etc/resolv.conf` on Unix, a
/// public fallback elsewhere (Windows has no plain-text resolver config).
pub fn system_dns_server() -> Option<IpAddr> {
    if !cfg!(target_os = "windows") {
        if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in resolv.lines() {
                if let Some(server) = line.strip_prefix("nameserver ") {
                    if let Ok(ip) = server.trim().parse() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
}

// --------------------------------------------------------------- portscan ----

/// TCP connect port scan of a single target (host or IP).
pub fn portscan(
    target: &str,
    ports: &[u16],
    concurrency: usize,
    timeout_ms: u64,
) -> Result<PortScanResult> {
    if ports.is_empty() {
        bail!("no ports to scan");
    }
    let target = target.trim();
    let ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let resolved = (target, 0)
                .to_socket_addrs()
                .ok()
                .and_then(|addrs| addrs.map(|a| a.ip()).next());
            resolved.ok_or_else(|| anyhow!("cannot resolve target '{target}'"))?
        }
    };
    let start = Instant::now();
    let hosts = vec![ip];
    let mut open: Vec<OpenPort> = sweep(&hosts, ports, concurrency, timeout_ms)
        .into_iter()
        .map(|hit| OpenPort {
            port: hit.port,
            service: service_name(hit.port).map(str::to_string),
            elapsed_ms: hit.elapsed_ms,
        })
        .collect();
    open.sort_by_key(|p| p.port);
    let open_count = open.len();
    Ok(PortScanResult {
        target: target.to_string(),
        ip,
        ports_scanned: ports.len(),
        open_count,
        open,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn parse_cidr_normalizes_host_bits() {
        assert_eq!(
            parse_cidr("192.168.1.77/24").unwrap(),
            ("192.168.1.0".parse().unwrap(), 24)
        );
        assert_eq!(
            parse_cidr("10.0.0.5").unwrap(),
            ("10.0.0.5".parse().unwrap(), 32)
        );
        assert!(parse_cidr("192.168.1.0/33").is_err());
        assert!(parse_cidr("not-an-ip/24").is_err());
        assert!(parse_cidr("::1/64").is_err(), "IPv4 only for scans");
    }

    #[test]
    fn cidr_hosts_enumerates_and_limits() {
        let hosts = cidr_hosts("192.168.1.0".parse().unwrap(), 30).unwrap();
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0].to_string(), "192.168.1.0");
        assert_eq!(hosts[3].to_string(), "192.168.1.3");
        assert!(cidr_hosts("10.0.0.0".parse().unwrap(), 8).is_err());
    }

    #[test]
    fn parse_port_spec_variants() {
        assert_eq!(parse_port_spec("80,443,80").unwrap(), vec![80, 443]);
        assert_eq!(parse_port_spec("10-12").unwrap(), vec![10, 11, 12]);
        assert_eq!(parse_port_spec("80,90-92").unwrap(), vec![80, 90, 91, 92]);
        assert_eq!(parse_port_spec("COMMON").unwrap(), COMMON_PORTS.to_vec());
        assert!(parse_port_spec("").is_err());
        assert!(parse_port_spec("0").is_err());
        assert!(parse_port_spec("5-2").is_err());
        assert!(parse_port_spec("1-99999").is_err());
    }

    #[test]
    fn service_names_cover_common_ports() {
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(8080), Some("http"));
        assert_eq!(service_name(12345), None);
    }

    #[test]
    fn sweep_finds_open_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hosts = vec![IpAddr::from([127, 0, 0, 1])];
        let hits = sweep(&hosts, &[port, 1, 2, 3], 4, 500);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].port, port);
        assert_eq!(hits[0].ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn portscan_reports_open_and_sorted_ports() {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut ports: Vec<u16> = vec![
            a.local_addr().unwrap().port(),
            b.local_addr().unwrap().port(),
        ];
        ports.sort();
        let result = portscan("127.0.0.1", &ports, 2, 500).unwrap();
        assert_eq!(result.open_count, 2);
        assert_eq!(result.open[0].port, ports[0]);
        assert_eq!(result.open[1].port, ports[1]);
        assert_eq!(result.ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn portscan_resolves_hostname() {
        let result = portscan("localhost", &[1], 1, 300).unwrap();
        assert_eq!(result.ports_scanned, 1);
        assert!(result.open.is_empty());
    }

    #[test]
    fn netscan_finds_loopback_device_via_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = netscan("127.0.0.0/30", &[port], 4, 300, false).unwrap();
        assert_eq!(result.hosts_total, 4);
        assert!(result.devices_found >= 1, "loopback must be discovered");
        let device = result
            .devices
            .iter()
            .find(|d| d.ip.to_string() == "127.0.0.1")
            .expect("device");
        assert_eq!(device.open_ports[0].port, port);
        assert!(device.via.iter().any(|v| v == "tcp"));
    }

    #[test]
    fn permission_gate_blocks_without_ack() {
        let err = ensure_scan_permission("netscan", false).unwrap_err();
        let gate = err
            .downcast_ref::<PermissionRequired>()
            .expect("gate error");
        assert_eq!(gate.action, "netscan");
        ensure_scan_permission("portscan", true).unwrap();
    }
}
