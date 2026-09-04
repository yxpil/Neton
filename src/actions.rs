//! Implementations of all neton actions (info / interfaces / ports / dns /
//! ping / probe / http).
//!
//! Pure functions returning serde-serializable models. Observation-level
//! failures (unreachable host, NXDOMAIN, refused connection) are returned as
//! data (`ok: false`) so agents can read them, while hard failures (no access
//! to the socket table, invalid input) surface as `anyhow::Error`.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sysinfo::System;

use crate::models::{
    DnsResult, HostInfo, HttpResult, InterfaceInfo, PingResult, PortEntry, ProbeItem, ProbeResult,
};

/// Default TCP port for `ping` (HTTPS).
pub const DEFAULT_PING_PORT: u16 = 443;
/// Default connect timeout (ms) for `ping` / `probe`.
pub const DEFAULT_TIMEOUT_MS: u64 = 2000;
/// Default request timeout (ms) for `http`.
pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 5000;
/// Default maximum body characters kept by `http`.
pub const DEFAULT_HTTP_BODY_MAX: usize = 500;
/// Default concurrency for `probe`.
pub const DEFAULT_PROBE_CONCURRENCY: usize = 32;

/// Actions exposed by `serve` (`POST /invoke`) and bare `neton` stdin mode.
/// The last four are network scans and require the explicit authorization
/// acknowledgement (`--yes-i-have-permission` / `NETON_I_HAVE_PERMISSION=yes`;
/// over HTTP the server itself must be started with that acknowledgement).
pub const ACTIONS: [&str; 11] = [
    "info",
    "interfaces",
    "ports",
    "dns",
    "ping",
    "probe",
    "http",
    "arp",
    "netscan",
    "portscan",
    "device",
];

/// Hard upper bound for probe concurrency.
const MAX_PROBE_CONCURRENCY: usize = 256;
/// Hard upper bound for user-supplied timeouts (ms).
const MAX_TIMEOUT_MS: u64 = 600_000;

/// Headers whose values are never echoed verbatim.
const SENSITIVE_HEADERS: [&str; 4] = [
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
];

// ---------------------------------------------------------------- info ----

/// Best-effort default outbound IPv4: a UDP "connect" to 8.8.8.8 only picks
/// the local address via the routing table — no packet is ever sent.
pub fn outbound_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Host overview: hostname, OS, arch, default outbound IP.
pub fn info() -> Result<HostInfo> {
    let os = System::long_os_version().or_else(|| {
        System::name().map(|name| match System::os_version() {
            Some(version) => format!("{name} {version}"),
            None => name,
        })
    });
    Ok(HostInfo {
        hostname: System::host_name(),
        os,
        arch: std::env::consts::ARCH.to_string(),
        outbound_ip: outbound_ip(),
    })
}

// ---------------------------------------------------------- interfaces ----

/// MAC address per interface name, from sysinfo (cross-platform). All-zero
/// MACs (loopback and some virtual devices) are dropped.
fn mac_addresses() -> BTreeMap<String, String> {
    let networks = sysinfo::Networks::new_with_refreshed_list();
    networks
        .iter()
        .filter_map(|(name, data)| {
            let mac = data.mac_address().to_string();
            if mac.is_empty() || mac == "00:00:00:00:00:00" {
                None
            } else {
                Some((name.clone(), mac))
            }
        })
        .collect()
}

/// Network interfaces: name, IPv4/IPv6, MAC, best-effort status.
pub fn interfaces() -> Result<Vec<InterfaceInfo>> {
    let addrs = if_addrs::get_if_addrs().context("failed to enumerate network interfaces")?;
    let macs = mac_addresses();

    let mut out: Vec<InterfaceInfo> = Vec::new();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    for iface in addrs {
        let ip = iface.ip();
        let entry = match index.get(&iface.name) {
            Some(&i) => &mut out[i],
            None => {
                out.push(InterfaceInfo {
                    name: iface.name.clone(),
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    mac: macs.get(&iface.name).cloned(),
                    status: "down".into(),
                    loopback: false,
                });
                index.insert(iface.name.clone(), out.len() - 1);
                out.last_mut().expect("just pushed")
            }
        };
        match ip {
            IpAddr::V4(_) => entry.ipv4.push(ip),
            IpAddr::V6(_) => entry.ipv6.push(ip),
        }
        if iface.is_loopback() {
            entry.loopback = true;
        }
    }
    for entry in &mut out {
        if !entry.ipv4.is_empty() || !entry.ipv6.is_empty() {
            entry.status = "up".into();
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- ports ----

/// Listening TCP sockets plus bound UDP sockets, with owning process.
pub fn ports(pid_filter: Option<u32>) -> Result<Vec<PortEntry>> {
    let families = netstat2::AddressFamilyFlags::IPV4 | netstat2::AddressFamilyFlags::IPV6;
    let protocols = netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP;
    let sockets = netstat2::get_sockets_info(families, protocols)
        .context("failed to enumerate local sockets")?;

    let mut pid_list: Vec<sysinfo::Pid> = sockets
        .iter()
        .flat_map(|socket| socket.associated_pids.iter())
        .copied()
        .map(sysinfo::Pid::from_u32)
        .collect();
    if let Some(filter) = pid_filter {
        pid_list = vec![sysinfo::Pid::from_u32(filter)];
    }
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&pid_list), true);
    let mut process_name = |pid: Option<u32>| -> Option<String> {
        let pid = pid?;
        if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
            let name = process.name().to_string_lossy().into_owned();
            if !name.is_empty() {
                return Some(name);
            }
        }
        // A partial refresh can transiently miss a live process (observed on
        // macOS under load) — fall back to a full refresh before giving up.
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let name = sys
            .process(sysinfo::Pid::from_u32(pid))?
            .name()
            .to_string_lossy()
            .into_owned();
        (!name.is_empty()).then_some(name)
    };

    let mut out: Vec<PortEntry> = Vec::new();
    for socket in sockets {
        let pid = socket.associated_pids.first().copied();
        if let Some(filter) = pid_filter {
            if pid != Some(filter) {
                continue;
            }
        }
        let process = process_name(pid);
        match socket.protocol_socket_info {
            netstat2::ProtocolSocketInfo::Tcp(tcp) => {
                if tcp.state != netstat2::TcpState::Listen {
                    continue;
                }
                out.push(PortEntry {
                    proto: "tcp".into(),
                    local_addr: SocketAddr::new(tcp.local_addr, tcp.local_port).to_string(),
                    local_ip: Some(tcp.local_addr.to_string()),
                    local_port: tcp.local_port,
                    pid,
                    process,
                    state: Some(format!("{:?}", tcp.state)),
                });
            }
            netstat2::ProtocolSocketInfo::Udp(udp) => {
                // Port-0 UDP entries are unbound pseudo-sockets (seen on
                // macOS), not real listening ports — skip them.
                if udp.local_port == 0 {
                    continue;
                }
                out.push(PortEntry {
                    proto: "udp".into(),
                    local_addr: SocketAddr::new(udp.local_addr, udp.local_port).to_string(),
                    local_ip: Some(udp.local_addr.to_string()),
                    local_port: udp.local_port,
                    pid,
                    process,
                    state: None,
                });
            }
        }
    }
    out.sort_by(|a, b| (a.local_port, &a.proto).cmp(&(b.local_port, &b.proto)));
    Ok(out)
}

// ------------------------------------------------------------------ dns ----

/// Resolve a host via the system resolver (`std::net::ToSocketAddrs`).
pub fn dns(host: &str) -> DnsResult {
    let start = Instant::now();
    let elapsed_ms = || start.elapsed().as_millis() as u64;
    match (host, 0).to_socket_addrs() {
        Ok(addrs) => {
            let mut ipv4: Vec<IpAddr> = Vec::new();
            let mut ipv6: Vec<IpAddr> = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                let bucket = match ip {
                    IpAddr::V4(_) => &mut ipv4,
                    IpAddr::V6(_) => &mut ipv6,
                };
                if !bucket.contains(&ip) {
                    bucket.push(ip);
                }
            }
            DnsResult {
                host: host.into(),
                ok: true,
                ipv4,
                ipv6,
                elapsed_ms: elapsed_ms(),
                error: None,
            }
        }
        Err(err) => DnsResult {
            host: host.into(),
            ok: false,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            elapsed_ms: elapsed_ms(),
            error: Some(err.to_string()),
        },
    }
}

// ----------------------------------------------------------------- ping ----

/// TCP connect probe (not ICMP): success/failure plus elapsed time.
pub fn ping(host: &str, port: u16, timeout_ms: u64) -> PingResult {
    let timeout_ms = timeout_ms.clamp(1, MAX_TIMEOUT_MS);
    let start = Instant::now();
    let elapsed_ms = || start.elapsed().as_millis() as u64;
    let base = |ok: bool, ip: Option<IpAddr>, error: Option<String>| PingResult {
        host: host.into(),
        port,
        ok,
        elapsed_ms: elapsed_ms(),
        ip,
        error,
    };

    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(err) => {
            return base(false, None, Some(format!("resolve failed: {err}")));
        }
    };
    if addrs.is_empty() {
        return base(false, None, Some("resolve returned no addresses".into()));
    }
    let mut last_error: Option<String> = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
            Ok(_) => return base(true, Some(addr.ip()), None),
            Err(err) => last_error = Some(format!("{}: {err}", addr.ip())),
        }
    }
    base(false, None, last_error)
}

// ---------------------------------------------------------------- probe ----

/// Parse one `host:port` / `[v6:addr]:port` probe target.
pub fn parse_target(target: &str) -> Result<(String, u16)> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow!("target '{target}' must be [host]:port"))?;
        let port: u16 = port
            .parse()
            .with_context(|| format!("invalid port in target '{target}'"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("target '{target}' must be host:port"))?;
    if host.contains(':') {
        bail!("target '{target}' must be [host]:port for IPv6 literals");
    }
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in target '{target}'"))?;
    Ok((host.to_string(), port))
}

/// Concurrently TCP-probe many `host:port` targets with a thread pool.
pub fn probe(targets: &[String], concurrency: usize, timeout_ms: u64) -> Result<ProbeResult> {
    if targets.is_empty() {
        bail!("no targets given");
    }
    let timeout_ms = timeout_ms.clamp(1, MAX_TIMEOUT_MS);
    let concurrency = concurrency
        .clamp(1, MAX_PROBE_CONCURRENCY)
        .min(targets.len());

    let targets = Arc::new(targets.to_vec());
    let (tx, rx) = mpsc::channel::<(usize, ProbeItem)>();
    let next_index = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let tx = tx.clone();
        let next_index = Arc::clone(&next_index);
        let targets = Arc::clone(&targets);
        workers.push(std::thread::spawn(move || loop {
            let idx = next_index.fetch_add(1, Ordering::Relaxed);
            if idx >= targets.len() {
                break;
            }
            let target = targets[idx].clone();
            let item = match parse_target(&target) {
                Ok((host, port)) => {
                    let result = ping(&host, port, timeout_ms);
                    ProbeItem {
                        target,
                        ok: result.ok,
                        elapsed_ms: result.elapsed_ms,
                        error: result.error,
                    }
                }
                Err(err) => ProbeItem {
                    target,
                    ok: false,
                    elapsed_ms: 0,
                    error: Some(err.to_string()),
                },
            };
            if tx.send((idx, item)).is_err() {
                break;
            }
        }));
    }
    drop(tx);

    let mut by_index: BTreeMap<usize, ProbeItem> = BTreeMap::new();
    for (idx, item) in rx {
        by_index.insert(idx, item);
    }
    for worker in workers {
        let _ = worker.join();
    }

    let items: Vec<ProbeItem> = by_index.into_values().collect();
    let open = items.iter().filter(|item| item.ok).count();
    Ok(ProbeResult {
        total: targets.len(),
        open,
        concurrency,
        items,
    })
}

// ----------------------------------------------------------------- http ----

/// HTTP request summary via ureq: status, timing, redacted headers and a
/// truncated body preview.
pub fn http(url: &str, method: &str, timeout_ms: u64, body_max: usize) -> Result<HttpResult> {
    let timeout_ms = timeout_ms.clamp(1, MAX_TIMEOUT_MS);
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(timeout_ms))
        .user_agent(concat!("neton/", env!("CARGO_PKG_VERSION")))
        .build();
    let method = method.trim().to_ascii_uppercase();

    let start = Instant::now();
    let response = match agent.request(&method, url).call() {
        Ok(response) => response,
        // Any HTTP response — including 4xx/5xx — is a valid observation.
        Err(ureq::Error::Status(_, response)) => response,
        Err(err) => {
            return Ok(HttpResult {
                ok: false,
                url: url.into(),
                final_url: None,
                status: None,
                elapsed_ms: start.elapsed().as_millis() as u64,
                headers: BTreeMap::new(),
                body: None,
                error: Some(err.to_string()),
            });
        }
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let status = response.status();
    let final_url = response.get_url().to_string();

    let mut headers: BTreeMap<String, Value> = BTreeMap::new();
    for name in response.headers_names() {
        let values: Vec<&str> = response.all(&name);
        if SENSITIVE_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            headers.insert(
                name,
                Value::Array(
                    values
                        .iter()
                        .map(|value| json!({ "redacted": true, "length": value.chars().count() }))
                        .collect(),
                ),
            );
        } else if values.len() == 1 {
            headers.insert(name.clone(), json!(values[0]));
        } else {
            headers.insert(name.clone(), json!(values));
        }
    }

    // Read at most enough bytes for `body_max` characters (UTF-8 worst case:
    // 4 bytes per character) so huge bodies never hit memory.
    let mut raw = Vec::new();
    let _ = response
        .into_reader()
        .take((body_max as u64).saturating_mul(4).saturating_add(4))
        .read_to_end(&mut raw);
    let body: String = String::from_utf8_lossy(&raw)
        .chars()
        .take(body_max)
        .collect();

    Ok(HttpResult {
        ok: true,
        url: url.into(),
        final_url: Some(final_url),
        status: Some(status),
        elapsed_ms,
        headers,
        body: Some(body),
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_accepts_host_port() {
        assert_eq!(
            parse_target("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
    }

    #[test]
    fn parse_target_accepts_ipv6_brackets() {
        assert_eq!(parse_target("[::1]:8753").unwrap(), ("::1".into(), 8753));
    }

    #[test]
    fn parse_target_rejects_missing_port() {
        assert!(parse_target("example.com").is_err());
    }

    #[test]
    fn parse_target_rejects_bad_port() {
        assert!(parse_target("example.com:notaport").is_err());
    }

    #[test]
    fn parse_target_rejects_bare_ipv6() {
        assert!(parse_target("::1:8753").is_err());
    }

    #[test]
    fn outbound_ip_is_none_or_valid() {
        // Must never panic; on an offline CI runner it simply stays None.
        if let Some(ip) = outbound_ip() {
            assert!(ip.is_ipv4() || ip.is_ipv6());
        }
    }
}
