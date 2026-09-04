//! System ARP / neighbor table (cross-platform, read-only, no root).
//!
//! Output of the platform tool is parsed by pure functions so each format is
//! unit-testable:
//! - macOS: `arp -an`
//! - Linux: `ip neigh show` (falls back to `arp -an`)
//! - Windows: `arp -a`

use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result};

use crate::models::ArpEntry;
use crate::oui::vendor_for_mac;

/// One raw (ip, mac, interface, state) tuple parsed from platform output.
type RawEntry = (String, Option<String>, Option<String>, Option<String>);

/// Read the system ARP / neighbor table.
pub fn read_arp_table() -> Result<Vec<ArpEntry>> {
    let entries = if cfg!(target_os = "macos") {
        run("arp", &["-an"]).map(|out| parse_arp_macos(&out))
    } else if cfg!(target_os = "windows") {
        run("arp", &["-a"]).map(|out| parse_arp_windows(&out))
    } else {
        run("ip", &["neigh", "show"])
            .map(|out| parse_ip_neigh(&out))
            .or_else(|_| run("arp", &["-an"]).map(|out| parse_arp_linux_arp(&out)))
    }?;
    Ok(entries
        .into_iter()
        .filter_map(|(ip, mac, interface, state)| {
            let ip: IpAddr = ip.parse().ok()?;
            // Normalize separators/case once; incomplete rows have no MAC.
            let mac = mac.map(|m| normalize_mac(&m));
            let vendor = mac.as_deref().and_then(vendor_for_mac).map(str::to_string);
            Some(ArpEntry {
                ip,
                mac,
                vendor,
                interface,
                state,
            })
        })
        .collect())
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{program} {args:?}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`{program} {args:?}` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Normalize a MAC to lowercase colon-separated form. macOS `arp` may drop
/// leading zeros per group (`da:6b:7:66:d1:c`), so groups are zero-padded.
fn normalize_mac(mac: &str) -> String {
    let cleaned = mac.trim().replace('-', ":");
    let groups: Vec<String> = if cleaned.contains(':') {
        cleaned
            .split(':')
            .filter(|group| !group.is_empty())
            .map(|group| format!("{:0>2}", group.to_ascii_lowercase()))
            .collect()
    } else {
        cleaned
            .to_ascii_lowercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).into_owned())
            .collect()
    };
    groups.join(":")
}

/// Parse `arp -an` from macOS:
/// `? (192.168.1.1) at a4:2b:8c:11:22:33 on en0 ifscope [ethernet]`
pub fn parse_arp_macos(output: &str) -> Vec<RawEntry> {
    output
        .lines()
        .filter_map(|line| {
            let open = line.find('(')?;
            let close = line.find(')')?;
            let ip = line.get(open + 1..close)?.trim().to_string();
            let rest = line.get(close + 1..)?;
            let rest = rest.strip_prefix(" at ")?;
            if rest.starts_with("(incomplete)") {
                let interface = rest.split(" on ").nth(1)?.split_whitespace().next();
                return Some((
                    ip,
                    None,
                    interface.map(str::to_string),
                    Some("incomplete".into()),
                ));
            }
            let mut parts = rest.splitn(3, " on ");
            let mac = parts.next()?.split_whitespace().next()?.to_string();
            let tail = parts.next().unwrap_or("");
            let interface = tail.split_whitespace().next().map(str::to_string);
            Some((ip, Some(mac), interface, None))
        })
        .collect()
}

/// Parse `ip neigh show` from Linux:
/// `192.168.1.1 dev wlan0 lladdr a4:2b:8c:11:22:33 REACHABLE`
pub fn parse_ip_neigh(output: &str) -> Vec<RawEntry> {
    output
        .lines()
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            let ip = tokens.next()?.trim().to_string();
            let mut interface = None;
            let mut mac = None;
            let mut state = None;
            while let Some(token) = tokens.next() {
                match token {
                    "dev" => interface = tokens.next().map(str::to_string),
                    "lladdr" => mac = tokens.next().map(str::to_string),
                    other if other.chars().all(|c| c.is_ascii_uppercase()) => {
                        state = Some(other.into())
                    }
                    _ => {}
                }
            }
            (!ip.is_empty()).then_some((ip, mac, interface, state))
        })
        .collect()
}

/// Parse `arp -an` from Linux (`procps-ng` / busybox style):
/// `? (192.168.1.1) at a4:2b:8c:11:22:33 [ether] on wlan0`
pub fn parse_arp_linux_arp(output: &str) -> Vec<RawEntry> {
    output
        .lines()
        .filter_map(|line| {
            let open = line.find('(')?;
            let close = line.find(')')?;
            let ip = line.get(open + 1..close)?.trim().to_string();
            let rest = line.get(close + 1..)?;
            let rest = rest.strip_prefix(" at ")?;
            if rest.starts_with("<incomplete>") {
                let interface = rest.split(" on ").nth(1)?.split_whitespace().next();
                return Some((
                    ip,
                    None,
                    interface.map(str::to_string),
                    Some("incomplete".into()),
                ));
            }
            let mut parts = rest.splitn(2, " on ");
            let mac = parts.next()?.split_whitespace().next()?.to_string();
            let interface = parts.next().map(|tail| {
                tail.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string()
            });
            Some((ip, Some(mac), interface, None))
        })
        .collect()
}

/// Parse `arp -a` from Windows:
/// `  192.168.1.1          a4-2b-8c-11-22-33     dynamic`
pub fn parse_arp_windows(output: &str) -> Vec<RawEntry> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with("Interface:")
                || line.starts_with("Internet Address")
            {
                return None;
            }
            let mut tokens = line.split_whitespace();
            let ip = tokens.next()?.to_string();
            if ip.parse::<IpAddr>().is_err() {
                return None;
            }
            let mac = tokens.next().filter(|m| m.contains('-') || m.contains(':'));
            let state = tokens.next().map(str::to_string);
            Some((ip, mac.map(str::to_string), None, state))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_arp_output() {
        let out = concat!(
            "? (192.168.1.1) at a4:2b:8c:11:22:33 on en0 ifscope [ethernet]\n",
            "? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n",
            "? (192.168.1.3) at f0:18:98:aa:bb:cc on en0 ifscope [ethernet]\n",
        );
        let entries = parse_arp_macos(out);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "192.168.1.1");
        assert_eq!(entries[0].1.as_deref(), Some("a4:2b:8c:11:22:33"));
        assert_eq!(entries[0].2.as_deref(), Some("en0"));
        assert_eq!(entries[1].1, None);
        assert_eq!(entries[1].3.as_deref(), Some("incomplete"));
        assert_eq!(entries[2].1.as_deref(), Some("f0:18:98:aa:bb:cc"));
    }

    #[test]
    fn parses_ip_neigh_output() {
        let out = concat!(
            "192.168.1.1 dev wlan0 lladdr a4:2b:8c:11:22:33 REACHABLE\n",
            "192.168.1.2 dev wlan0  INCOMPLETE\n",
            "fe80::1 dev wlan0 lladdr a4:2b:8c:11:22:33 router STALE\n",
        );
        let entries = parse_ip_neigh(out);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "192.168.1.1");
        assert_eq!(entries[0].1.as_deref(), Some("a4:2b:8c:11:22:33"));
        assert_eq!(entries[0].2.as_deref(), Some("wlan0"));
        assert_eq!(entries[0].3.as_deref(), Some("REACHABLE"));
        assert_eq!(entries[1].1, None);
        assert_eq!(entries[2].0, "fe80::1");
        assert_eq!(entries[2].3.as_deref(), Some("STALE"));
    }

    #[test]
    fn parses_linux_arp_output() {
        let out = "? (192.168.1.1) at a4:2b:8c:11:22:33 [ether] on wlan0\n";
        let entries = parse_arp_linux_arp(out);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "192.168.1.1");
        assert_eq!(entries[0].1.as_deref(), Some("a4:2b:8c:11:22:33"));
        assert_eq!(entries[0].2.as_deref(), Some("wlan0"));
    }

    #[test]
    fn parses_windows_arp_output() {
        let out = concat!(
            "\nInterface: 192.168.1.10 --- 0x8\n",
            "  Internet Address          Physical Address      Type\n",
            "  192.168.1.1           a4-2b-8c-11-22-33     dynamic\n",
            "  224.0.0.251           01-00-5e-00-00-fb     static\n",
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n",
        );
        let entries = parse_arp_windows(out);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "192.168.1.1");
        assert_eq!(entries[0].1.as_deref(), Some("a4-2b-8c-11-22-33"));
        assert_eq!(entries[0].3.as_deref(), Some("dynamic"));
        assert_eq!(entries[2].1.as_deref(), Some("ff-ff-ff-ff-ff-ff"));
    }

    #[test]
    fn normalizes_and_attaches_vendor() {
        let entries: Vec<ArpEntry> =
            parse_ip_neigh("192.168.1.1 dev wlan0 lladdr A4-2B-8C-11-22-33 REACHABLE\n")
                .into_iter()
                .filter_map(|(ip, mac, interface, state)| {
                    let ip: IpAddr = ip.parse().ok()?;
                    let mac = mac.map(|m| normalize_mac(&m));
                    let vendor = mac.as_deref().and_then(vendor_for_mac).map(str::to_string);
                    Some(ArpEntry {
                        ip,
                        mac,
                        vendor,
                        interface,
                        state,
                    })
                })
                .collect();
        assert_eq!(entries[0].mac.as_deref(), Some("a4:2b:8c:11:22:33"));
        assert_eq!(entries[0].vendor.as_deref(), Some("TP-Link"));
    }

    #[test]
    fn normalize_mac_pads_dropped_leading_zeros() {
        // macOS `arp -an` prints randomized MACs without leading zeros.
        assert_eq!(normalize_mac("da:6b:7:66:d1:c"), "da:6b:07:66:d1:0c");
        assert_eq!(normalize_mac("A4-2B-8C-11-22-33"), "a4:2b:8c:11:22:33");
        assert_eq!(normalize_mac("a42b8c112233"), "a4:2b:8c:11:22:33");
    }
}
