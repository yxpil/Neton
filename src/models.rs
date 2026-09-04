//! Output data structures shared by the CLI and the HTTP API.
//!
//! Every field below is part of neton's public JSON contract: the CLI prints
//! these structs as JSON and the README API tables are derived from them.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Result of `neton info`: a static host overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// OS hostname, e.g. `workstation-01`; `null` when the OS refuses to tell.
    pub hostname: Option<String>,
    /// Human readable OS name and version, e.g. `macOS 15.5`.
    pub os: Option<String>,
    /// CPU architecture, e.g. `x86_64` or `aarch64`.
    pub arch: String,
    /// Default outbound IPv4 address probed via UDP connect to 8.8.8.8 (no
    /// packet is actually sent); `null` when offline or unrouted.
    pub outbound_ip: Option<IpAddr>,
}

/// One network interface as reported by `neton interfaces`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// Interface name, e.g. `en0` / `eth0` / `Ethernet 2`.
    pub name: String,
    /// All IPv4 addresses assigned to this interface (may be empty).
    pub ipv4: Vec<IpAddr>,
    /// All IPv6 addresses assigned to this interface (may be empty).
    pub ipv6: Vec<IpAddr>,
    /// MAC address, e.g. `a4:83:e7:aa:bb:cc`; `null` when unknown.
    pub mac: Option<String>,
    /// Best-effort link status: `up` when the interface has at least one IP
    /// address assigned, otherwise `down`.
    pub status: String,
    /// True for loopback interfaces.
    pub loopback: bool,
}

/// One listening socket as reported by `neton ports`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortEntry {
    /// Transport protocol: `tcp` or `udp`.
    pub proto: String,
    /// Local address as `ip:port` (IPv6 rendered as `[::1]:8753`).
    pub local_addr: String,
    /// Local IP part, e.g. `127.0.0.1` or `0.0.0.0` for a wildcard socket.
    pub local_ip: Option<String>,
    /// Local port number.
    pub local_port: u16,
    /// Owning process id; `null` when the platform cannot provide it.
    pub pid: Option<u32>,
    /// Owning process name; `null` when the pid is unknown or the process
    /// exited between listing and lookup.
    pub process: Option<String>,
    /// TCP socket state, e.g. `Listen`; always `null` for UDP (UDP has no
    /// connection state).
    pub state: Option<String>,
}

/// Result of `neton dns <HOST>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    /// The host that was resolved.
    pub host: String,
    /// Whether resolution succeeded.
    pub ok: bool,
    /// Resolved IPv4 addresses (may be empty).
    pub ipv4: Vec<IpAddr>,
    /// Resolved IPv6 addresses (may be empty).
    pub ipv6: Vec<IpAddr>,
    /// Resolution time in milliseconds.
    pub elapsed_ms: u64,
    /// Error message when `ok` is false, otherwise `null`.
    pub error: Option<String>,
}

/// Result of `neton ping <HOST>` — a TCP connect probe, not ICMP, so no root
/// privileges are required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    /// Host that was probed.
    pub host: String,
    /// TCP port that was probed.
    pub port: u16,
    /// Whether the TCP connection succeeded.
    pub ok: bool,
    /// Connect time in milliseconds (measured until success or last failure).
    pub elapsed_ms: u64,
    /// Resolved address that was connected to; `null` on failure.
    pub ip: Option<IpAddr>,
    /// Error message when `ok` is false, otherwise `null`.
    pub error: Option<String>,
}

/// Result of a single target inside `neton probe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeItem {
    /// Original `host:port` target string.
    pub target: String,
    /// Whether the TCP connection succeeded.
    pub ok: bool,
    /// Connect time in milliseconds.
    pub elapsed_ms: u64,
    /// Error message when `ok` is false, otherwise `null`.
    pub error: Option<String>,
}

/// Result of `neton probe`: concurrent TCP probing of many targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Number of targets probed.
    pub total: usize,
    /// Number of targets that answered.
    pub open: usize,
    /// Concurrency actually used (capped at the number of targets).
    pub concurrency: usize,
    /// Per-target results, in the same order as the input targets.
    pub items: Vec<ProbeItem>,
}

/// Result of `neton http <URL>`: a request summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
    /// Whether an HTTP response was received (any status code counts as ok;
    /// `false` only when the request failed on transport level).
    pub ok: bool,
    /// URL that was requested.
    pub url: String,
    /// Final URL after redirects; `null` when the request failed.
    pub final_url: Option<String>,
    /// HTTP status code; `null` when the request failed on transport level.
    pub status: Option<u16>,
    /// Total request time in milliseconds.
    pub elapsed_ms: u64,
    /// Response headers. Sensitive values (`set-cookie`, `cookie`,
    /// `authorization`, `proxy-authorization`) are redacted to their length.
    pub headers: BTreeMap<String, Value>,
    /// First N characters of the response body (N = `--body-max`, default 500).
    pub body: Option<String>,
    /// Transport error message when `ok` is false, otherwise `null`.
    pub error: Option<String>,
}

/// One ARP / neighbor-table row as reported by `neton arp`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    /// Neighbor IP address.
    pub ip: IpAddr,
    /// MAC address normalized to lowercase colon form, e.g.
    /// `a4:2b:8c:11:22:33`; `null` for incomplete entries.
    pub mac: Option<String>,
    /// Vendor guessed from the embedded OUI table; `null` when unknown.
    pub vendor: Option<String>,
    /// Interface the neighbor was learned on, e.g. `en0`; platform-dependent.
    pub interface: Option<String>,
    /// Neighbor state as reported by the OS, e.g. `REACHABLE`, `incomplete`,
    /// `dynamic`; `null` when the platform does not report one.
    pub state: Option<String>,
}

/// One discovered device inside a `neton netscan` run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Device IP address.
    pub ip: IpAddr,
    /// MAC address from the ARP table; `null` when not (yet) learned.
    pub mac: Option<String>,
    /// Vendor from the embedded OUI table; `null` when unknown.
    pub vendor: Option<String>,
    /// Hostname via best-effort reverse DNS (PTR); `null` when unavailable.
    pub hostname: Option<String>,
    /// Ports that answered during the discovery sweep.
    pub open_ports: Vec<OpenPort>,
    /// How the device was discovered: a subset of `tcp` (answered the sweep)
    /// and `arp` (present in the ARP table).
    pub via: Vec<String>,
}

/// One open TCP port with its guessed service name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    /// Port number.
    pub port: u16,
    /// Well-known service name (`http`, `ssh`, …); `null` when unknown.
    pub service: Option<String>,
    /// Connect time in milliseconds.
    pub elapsed_ms: u64,
}

/// Result of `neton netscan <CIDR>`: subnet host discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetScanResult {
    /// The scanned range, normalized to `network/prefix`.
    pub cidr: String,
    /// Number of host addresses inside the range.
    pub hosts_total: usize,
    /// Discovery ports that were probed.
    pub ports_probed: Vec<u16>,
    /// Concurrency actually used.
    pub concurrency: usize,
    /// Connect timeout in milliseconds.
    pub timeout_ms: u64,
    /// Number of discovered devices.
    pub devices_found: usize,
    /// Discovered devices sorted by IP.
    pub devices: Vec<Device>,
    /// Total rows visible in the system ARP table (any range, diagnostics).
    pub arp_entries_seen: usize,
    /// Total scan duration in milliseconds.
    pub elapsed_ms: u64,
}

/// Result of `neton portscan <TARGET>`: TCP connect scan of one host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    /// Target as given (IP or hostname).
    pub target: String,
    /// Address actually scanned.
    pub ip: IpAddr,
    /// Number of ports probed.
    pub ports_scanned: usize,
    /// Number of ports that answered.
    pub open_count: usize,
    /// Open ports sorted ascending, with guessed service names.
    pub open: Vec<OpenPort>,
    /// Total scan duration in milliseconds.
    pub elapsed_ms: u64,
}

/// One HTTP fingerprint observation of a device management page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbe {
    /// Probed URL.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// `Server` response header; `null` when absent.
    pub server: Option<String>,
    /// `X-Powered-By` / `X-Generator` header; `null` when absent.
    pub powered_by: Option<String>,
    /// Page `<title>` (whitespace-collapsed); `null` when none.
    pub title: Option<String>,
}

/// One open port inside a `neton device` report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceReportPort {
    /// Port number.
    pub port: u16,
    /// Well-known service name; `null` when unknown.
    pub service: Option<String>,
    /// Connect time in milliseconds.
    pub elapsed_ms: u64,
}

/// Result of `neton device <IP>`: analysis of a single LAN device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceReport {
    /// Device IP address.
    pub ip: IpAddr,
    /// Hostname via best-effort reverse DNS (PTR); `null` when unavailable.
    pub hostname: Option<String>,
    /// MAC address from the ARP table; `null` when not (yet) learned.
    pub mac: Option<String>,
    /// Vendor from the embedded OUI table; `null` when unknown.
    pub vendor: Option<String>,
    /// Interface the neighbor was learned on; platform-dependent.
    pub interface: Option<String>,
    /// Neighbor state as reported by the OS; `null` when unknown.
    pub arp_state: Option<String>,
    /// Open ports found by the common-port probe.
    pub open_ports: Vec<DeviceReportPort>,
    /// HTTP(S) fingerprints of the device's management pages.
    pub http: Vec<HttpProbe>,
    /// Informational device-type guess derived from vendor, ports and page
    /// titles — never a certainty.
    pub guess: String,
    /// Total analysis duration in milliseconds.
    pub elapsed_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_info_serializes_expected_keys() {
        let v = serde_json::to_value(HostInfo {
            hostname: Some("box".into()),
            os: Some("TestOS 1.0".into()),
            arch: "x86_64".into(),
            outbound_ip: Some("10.0.0.2".parse().unwrap()),
        })
        .unwrap();
        assert_eq!(v["hostname"], "box");
        assert_eq!(v["os"], "TestOS 1.0");
        assert_eq!(v["arch"], "x86_64");
        assert_eq!(v["outbound_ip"], "10.0.0.2");
    }

    #[test]
    fn port_entry_nulls_unknown_pid_and_process() {
        let v = serde_json::to_value(PortEntry {
            proto: "tcp".into(),
            local_addr: "127.0.0.1:8753".into(),
            local_ip: Some("127.0.0.1".into()),
            local_port: 8753,
            pid: None,
            process: None,
            state: Some("Listen".into()),
        })
        .unwrap();
        assert_eq!(v["proto"], "tcp");
        assert_eq!(v["local_addr"], "127.0.0.1:8753");
        assert_eq!(v["local_port"], 8753);
        assert_eq!(v["pid"], Value::Null);
        assert_eq!(v["process"], Value::Null);
        assert_eq!(v["state"], "Listen");
    }

    #[test]
    fn dns_result_serializes_error_and_lists() {
        let v = serde_json::to_value(DnsResult {
            host: "localhost".into(),
            ok: true,
            ipv4: vec!["127.0.0.1".parse().unwrap()],
            ipv6: vec!["::1".parse().unwrap()],
            elapsed_ms: 3,
            error: None,
        })
        .unwrap();
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["ipv4"][0], "127.0.0.1");
        assert_eq!(v["ipv6"][0], "::1");
        assert_eq!(v["elapsed_ms"], 3);
        assert_eq!(v["error"], Value::Null);
    }

    #[test]
    fn ping_result_roundtrip() {
        let v = serde_json::to_value(PingResult {
            host: "example.com".into(),
            port: 443,
            ok: false,
            elapsed_ms: 120,
            ip: None,
            error: Some("refused".into()),
        })
        .unwrap();
        let back: PingResult = serde_json::from_value(v).unwrap();
        assert!(!back.ok);
        assert_eq!(back.error.as_deref(), Some("refused"));
    }

    #[test]
    fn probe_result_roundtrip_keeps_order() {
        let v = serde_json::to_value(ProbeResult {
            total: 2,
            open: 1,
            concurrency: 2,
            items: vec![
                ProbeItem {
                    target: "a:1".into(),
                    ok: true,
                    elapsed_ms: 1,
                    error: None,
                },
                ProbeItem {
                    target: "b:2".into(),
                    ok: false,
                    elapsed_ms: 2,
                    error: Some("x".into()),
                },
            ],
        })
        .unwrap();
        let back: ProbeResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.items.len(), 2);
        assert_eq!(back.items[0].target, "a:1");
        assert!(!back.items[1].ok);
    }

    #[test]
    fn http_result_headers_are_a_json_object() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Set-Cookie".into(),
            json!([{ "redacted": true, "length": 10 }]),
        );
        let v = serde_json::to_value(HttpResult {
            ok: true,
            url: "http://127.0.0.1:1/".into(),
            final_url: Some("http://127.0.0.1:1/".into()),
            status: Some(200),
            elapsed_ms: 5,
            headers,
            body: Some("hello".into()),
            error: None,
        })
        .unwrap();
        assert_eq!(v["status"], 200);
        assert_eq!(v["headers"]["Set-Cookie"][0]["redacted"], true);
        assert_eq!(v["headers"]["Set-Cookie"][0]["length"], 10);
        assert_eq!(v["body"], "hello");
    }
}
