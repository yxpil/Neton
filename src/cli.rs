//! CLI definitions (clap) plus the piped-stdin merge contract.
//!
//! When stdin is not a TTY (BIT exec mode), neton reads a JSON object from
//! stdin and merges it over the subcommand arguments — stdin wins.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

/// neton — structured local network observation for AI agents.
#[derive(Parser, Debug)]
#[command(
    name = "neton",
    version,
    about = "Structured local network observation and diagnostics for AI agents (JSON in, JSON out)",
    after_help = "All data is emitted as JSON on stdout; logs and errors go to stderr.\nWhen stdin is piped, a JSON object is read and merged over the arguments (stdin wins).\n\nScan actions (netscan / portscan / device) require explicit authorization:\npass --yes-i-have-permission or set NETON_I_HAVE_PERMISSION=yes — only scan\nnetworks you own or are authorized to test."
)]
pub struct Cli {
    /// Emit JSON (this is the default; the flag is kept for explicitness).
    #[arg(long, global = true)]
    pub json: bool,
    /// Pretty-print the JSON output with indentation.
    #[arg(long, global = true)]
    pub pretty: bool,
    /// Acknowledge you are authorized to run network scans on the target.
    #[arg(long, global = true)]
    pub yes_i_have_permission: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Host overview: hostname, OS, arch, default outbound IP
    Info,
    /// Network interfaces with IPv4/IPv6, MAC and status
    Interfaces,
    /// Listening TCP sockets and bound UDP sockets with owning process
    Ports(PortsArgs),
    /// Resolve a host via the system resolver
    Dns(DnsArgs),
    /// TCP connect probe (no ICMP, no root required)
    Ping(PingArgs),
    /// Concurrently TCP-probe many host:port targets
    Probe(ProbeArgs),
    /// HTTP request summary (status, timing, redacted headers, body preview)
    Http(HttpArgs),
    /// System ARP / neighbor table with vendor lookup (no root required)
    Arp,
    /// Discover live devices in a subnet (TCP sweep + ARP correlation) [scan]
    #[command(name = "netscan")]
    NetScan(NetScanArgs),
    /// TCP connect port scan of one target [scan]
    #[command(name = "portscan")]
    PortScan(PortScanArgs),
    /// Analyze one LAN device: hostname, MAC vendor, ports, HTTP fingerprint [scan]
    Device(DeviceArgs),
    /// Run the BIT Remote HTTP API server
    Serve(ServeArgs),
}

/// Arguments of `neton ports`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct PortsArgs {
    /// Only list sockets owned by this process id
    #[arg(long, value_name = "PID")]
    pub pid: Option<u32>,
}

/// Arguments of `neton dns`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct DnsArgs {
    /// Hostname to resolve
    #[arg(value_name = "HOST")]
    pub host: Option<String>,
}

/// Arguments of `neton ping`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct PingArgs {
    /// Host to probe
    #[arg(value_name = "HOST")]
    pub host: Option<String>,
    /// TCP port to probe (default 443)
    #[arg(short, long, value_name = "PORT")]
    pub port: Option<u16>,
    /// Connect timeout in milliseconds (default 2000)
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,
}

/// Arguments of `neton probe`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct ProbeArgs {
    /// Comma-separated targets, e.g. "example.com:443,127.0.0.1:8080"
    #[arg(value_name = "TARGETS")]
    pub targets: Option<String>,
    /// Maximum concurrent probes (default 32)
    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,
    /// Connect timeout in milliseconds (default 2000)
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,
}

/// Arguments of `neton http`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct HttpArgs {
    /// URL to request
    #[arg(value_name = "URL")]
    pub url: Option<String>,
    /// HTTP method (default GET)
    #[arg(long, value_name = "METHOD")]
    pub method: Option<String>,
    /// Request timeout in milliseconds (default 5000)
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,
    /// Maximum body characters to keep (default 500)
    #[arg(long, value_name = "N")]
    pub body_max: Option<usize>,
}

/// Arguments of `neton serve`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct ServeArgs {
    /// Bind address (default 127.0.0.1)
    #[arg(long, value_name = "HOST")]
    pub host: Option<String>,
    /// Port to listen on (default 8753)
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,
    /// Require "Authorization: Bearer <token>" on all endpoints except /health
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,
    /// Authorize scan actions (netscan / portscan / device) over /invoke
    #[arg(long)]
    pub yes_i_have_permission: bool,
}

/// Arguments of `neton netscan`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct NetScanArgs {
    /// IPv4 CIDR to scan, e.g. "192.168.1.0/24"
    #[arg(value_name = "CIDR")]
    pub cidr: Option<String>,
    /// Comma-separated discovery ports (default "22,80,443,445,3389,8080")
    #[arg(long, value_name = "PORTS")]
    pub ports: Option<String>,
    /// Maximum concurrent probes (default 128)
    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,
    /// Connect timeout in milliseconds (default 400)
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,
    /// Skip reverse-DNS hostname lookups
    #[arg(long)]
    pub no_rdns: bool,
}

/// Arguments of `neton portscan`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct PortScanArgs {
    /// Target IP or hostname
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,
    /// Ports to scan: "common" (default), a list "80,443", or a range "1-1024"
    #[arg(long, value_name = "PORTS")]
    pub ports: Option<String>,
    /// Maximum concurrent probes (default 200)
    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,
    /// Connect timeout in milliseconds (default 800)
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,
}

/// Arguments of `neton device`.
#[derive(Args, Debug, Default, Deserialize)]
pub struct DeviceArgs {
    /// Device IP address
    #[arg(value_name = "IP")]
    pub ip: Option<String>,
    /// Ports to probe: "common" (default), a list, or a range
    #[arg(long, value_name = "PORTS")]
    pub ports: Option<String>,
    /// Connect timeout in milliseconds (default 1000)
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,
    /// Maximum number of HTTP(S) fingerprint probes (default 2, max 4)
    #[arg(long, value_name = "N")]
    pub http_max: Option<usize>,
    /// Skip reverse-DNS hostname lookups
    #[arg(long)]
    pub no_rdns: bool,
}

/// Merge piped-stdin JSON over parsed CLI arguments (stdin wins).
pub trait MergeStdin {
    /// Read matching keys from `value` (a JSON object) and override fields.
    fn merge_stdin(&mut self, value: &Value) -> Result<()>;
}

fn take<T: DeserializeOwned>(value: &Value, key: &str) -> Result<Option<T>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => serde_json::from_value(raw.clone())
            .with_context(|| format!("invalid value for '{key}'")),
    }
}

impl MergeStdin for PortsArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(pid) = take(value, "pid")? {
            self.pid = Some(pid);
        }
        Ok(())
    }
}

impl MergeStdin for DnsArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(host) = take(value, "host")? {
            self.host = Some(host);
        }
        Ok(())
    }
}

impl MergeStdin for PingArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(host) = take(value, "host")? {
            self.host = Some(host);
        }
        if let Some(port) = take(value, "port")? {
            self.port = Some(port);
        }
        if let Some(timeout_ms) = take(value, "timeout_ms")? {
            self.timeout_ms = Some(timeout_ms);
        }
        Ok(())
    }
}

impl MergeStdin for ProbeArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        // "targets" may arrive as an array of "host:port" strings or as one
        // comma-separated string; both are normalized to the string form.
        if let Some(targets) = value.get("targets") {
            let joined = match targets {
                Value::Null => None,
                Value::String(s) => Some(s.clone()),
                Value::Array(items) => {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let Some(s) = item.as_str() else {
                            bail!("invalid value for 'targets': array items must be strings");
                        };
                        out.push(s.to_string());
                    }
                    Some(out.join(","))
                }
                _ => bail!("invalid value for 'targets': expected a string or an array"),
            };
            if let Some(joined) = joined {
                self.targets = Some(joined);
            }
        }
        if let Some(concurrency) = take(value, "concurrency")? {
            self.concurrency = Some(concurrency);
        }
        if let Some(timeout_ms) = take(value, "timeout_ms")? {
            self.timeout_ms = Some(timeout_ms);
        }
        Ok(())
    }
}

impl MergeStdin for HttpArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(url) = take(value, "url")? {
            self.url = Some(url);
        }
        if let Some(method) = take(value, "method")? {
            self.method = Some(method);
        }
        if let Some(timeout_ms) = take(value, "timeout_ms")? {
            self.timeout_ms = Some(timeout_ms);
        }
        if let Some(body_max) = take(value, "body_max")? {
            self.body_max = Some(body_max);
        }
        Ok(())
    }
}

impl MergeStdin for ServeArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(host) = take(value, "host")? {
            self.host = Some(host);
        }
        if let Some(port) = take(value, "port")? {
            self.port = Some(port);
        }
        if let Some(token) = take(value, "token")? {
            self.token = Some(token);
        }
        if let Some(flag) = take(value, "yes_i_have_permission")? {
            self.yes_i_have_permission = flag;
        }
        Ok(())
    }
}

impl MergeStdin for NetScanArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(cidr) = take(value, "cidr")? {
            self.cidr = Some(cidr);
        }
        if let Some(ports) = take(value, "ports")? {
            self.ports = Some(ports);
        }
        if let Some(concurrency) = take(value, "concurrency")? {
            self.concurrency = Some(concurrency);
        }
        if let Some(timeout_ms) = take(value, "timeout_ms")? {
            self.timeout_ms = Some(timeout_ms);
        }
        if let Some(no_rdns) = take(value, "no_rdns")? {
            self.no_rdns = no_rdns;
        }
        Ok(())
    }
}

impl MergeStdin for PortScanArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(target) = take(value, "target")? {
            self.target = Some(target);
        }
        if let Some(ports) = take(value, "ports")? {
            self.ports = Some(ports);
        }
        if let Some(concurrency) = take(value, "concurrency")? {
            self.concurrency = Some(concurrency);
        }
        if let Some(timeout_ms) = take(value, "timeout_ms")? {
            self.timeout_ms = Some(timeout_ms);
        }
        Ok(())
    }
}

impl MergeStdin for DeviceArgs {
    fn merge_stdin(&mut self, value: &Value) -> Result<()> {
        if let Some(ip) = take(value, "ip")? {
            self.ip = Some(ip);
        }
        if let Some(ports) = take(value, "ports")? {
            self.ports = Some(ports);
        }
        if let Some(timeout_ms) = take(value, "timeout_ms")? {
            self.timeout_ms = Some(timeout_ms);
        }
        if let Some(http_max) = take(value, "http_max")? {
            self.http_max = Some(http_max);
        }
        if let Some(no_rdns) = take(value, "no_rdns")? {
            self.no_rdns = no_rdns;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ping_merge_overrides_fields() {
        let mut args = PingArgs {
            host: Some("cli-host".into()),
            port: Some(1),
            timeout_ms: None,
        };
        args.merge_stdin(&json!({ "host": "stdin-host", "port": 8443 }))
            .unwrap();
        assert_eq!(args.host.as_deref(), Some("stdin-host"));
        assert_eq!(args.port, Some(8443));
        assert_eq!(args.timeout_ms, None);
    }

    #[test]
    fn merge_ignores_null_and_unknown_keys() {
        let mut args = DnsArgs {
            host: Some("cli-host".into()),
        };
        args.merge_stdin(&json!({ "host": null, "action": "dns", "extra": 1 }))
            .unwrap();
        assert_eq!(args.host.as_deref(), Some("cli-host"));
    }

    #[test]
    fn probe_merge_accepts_array_or_string() {
        let mut args = ProbeArgs::default();
        args.merge_stdin(&json!({ "targets": ["a:1", "b:2"] }))
            .unwrap();
        assert_eq!(args.targets.as_deref(), Some("a:1,b:2"));
        args.merge_stdin(&json!({ "targets": "c:3, d:4" })).unwrap();
        assert_eq!(args.targets.as_deref(), Some("c:3, d:4"));
    }

    #[test]
    fn merge_rejects_wrong_types() {
        let mut args = PortsArgs::default();
        assert!(args.merge_stdin(&json!({ "pid": "not-a-number" })).is_err());
    }
}
