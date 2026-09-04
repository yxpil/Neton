//! `neton device <IP>` — analysis of a single LAN device: MAC + vendor from
//! the ARP table, hostname via PTR, common port probe and HTTP fingerprint
//! (server header + page title) on the ports that answer.

use std::io::Read;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::models::{DeviceReport, DeviceReportPort, HttpProbe};
use crate::scan::{portscan, COMMON_PORTS};

/// Ports probed for HTTP fingerprints when found open (capped by http_max).
const HTTP_PROBE_PORTS: [u16; 4] = [80, 8080, 8000, 8009];

/// Ports probed for HTTPS fingerprints (GET still works for many routers).
const HTTPS_PROBE_PORTS: [u16; 2] = [443, 8443];

/// Default connect timeout (ms) for `device`.
pub const DEFAULT_DEVICE_TIMEOUT_MS: u64 = 1000;
/// Default number of HTTP(S) fingerprint probes for `device`.
pub const DEFAULT_HTTP_MAX: usize = 2;

/// Analyze one device. `ports` defaults to the common preset; `http_max`
/// bounds the number of HTTP(S) probes issued (max 4).
pub fn analyze(ip: IpAddr, ports: Option<&[u16]>, timeout_ms: u64, http_max: usize, rdns: bool) -> Result<DeviceReport> {
    let start = Instant::now();
    let ports = ports.unwrap_or(COMMON_PORTS).to_vec();

    // 1) TCP port probe.
    let scan = portscan(&ip.to_string(), &ports, 64, timeout_ms)?;

    // 2) ARP / vendor correlation.
    let arp_entry = crate::arp::read_arp_table()
        .unwrap_or_default()
        .into_iter()
        .find(|entry| entry.ip == ip);

    // 3) Reverse DNS.
    let hostname = if rdns {
        crate::scan::rdns_lookup(&ip)
    } else {
        None
    };

    // 4) HTTP(S) fingerprint on a few likely management ports that are open.
    let open_ports: Vec<u16> = scan.open.iter().map(|p| p.port).collect();
    let mut http_probes: Vec<HttpProbe> = Vec::new();
    let mut probe_budget = http_max.clamp(0, 4);
    'outer: for port in HTTP_PROBE_PORTS
        .into_iter()
        .chain(HTTPS_PROBE_PORTS.into_iter())
    {
        if probe_budget == 0 || !open_ports.contains(&port) {
            continue;
        }
        let scheme = if HTTPS_PROBE_PORTS.contains(&port) { "https" } else { "http" };
        let url = format!("{scheme}://{ip}:{port}/");
        if let Some(probe) = http_fingerprint(&url, timeout_ms) {
            probe_budget -= 1;
            http_probes.push(probe);
            if probe_budget == 0 {
                break 'outer;
            }
        }
    }

    // 5) Best-effort device-type guess from vendor + ports + fingerprints.
    let guess = guess_device_type(arp_entry.as_ref().and_then(|e| e.vendor.as_deref()), &open_ports, &http_probes);

    Ok(DeviceReport {
        ip,
        hostname,
        mac: arp_entry.as_ref().and_then(|e| e.mac.clone()),
        vendor: arp_entry.as_ref().and_then(|e| e.vendor.clone()),
        interface: arp_entry.as_ref().and_then(|e| e.interface.clone()),
        arp_state: arp_entry.as_ref().and_then(|e| e.state.clone()),
        open_ports: scan
            .open
            .iter()
            .map(|p| DeviceReportPort {
                port: p.port,
                service: p.service.clone(),
                elapsed_ms: p.elapsed_ms,
            })
            .collect(),
        http: http_probes,
        guess,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// GET the URL, redact headers like `neton http`, extract the `<title>`.
pub fn http_fingerprint(url: &str, timeout_ms: u64) -> Option<HttpProbe> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(timeout_ms.clamp(100, 30_000)))
        .user_agent(concat!("neton/", env!("CARGO_PKG_VERSION")))
        .redirects(1)
        .build();
    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return None,
    };
    let status = response.status();
    let server = response.header("server").map(str::to_string);
    let powered = response
        .header("x-powered-by")
        .or_else(|| response.header("x-generator"))
        .map(str::to_string);
    let mut raw = Vec::new();
    let _ = response
        .into_reader()
        .take(64 * 1024)
        .read_to_end(&mut raw);
    let body = String::from_utf8_lossy(&raw);
    let title = extract_title(&body);
    Some(HttpProbe {
        url: url.to_string(),
        status,
        server,
        powered_by: powered,
        title,
    })
}

/// Case-insensitive `<title>…</title>` extraction (first 16 KiB of the body).
/// The original character case is preserved; only the search is case-folded.
pub fn extract_title(body: &str) -> Option<String> {
    let head = &body[..body.len().min(16 * 1024)];
    let lower = head.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let gt = lower[open..].find('>')? + open;
    let rest = head.get(gt + 1..)?;
    let close = rest.to_ascii_lowercase().find("</title")?;
    let title: String = rest[..close].split_whitespace().collect::<Vec<_>>().join(" ");
    (!title.is_empty()).then_some(title)
}

/// Heuristic device-type guess. Purely informational — never a certainty.
fn guess_device_type(vendor: Option<&str>, ports: &[u16], http: &[HttpProbe]) -> String {
    let mut hints: Vec<String> = Vec::new();
    if let Some(vendor) = vendor {
        hints.push(format!("vendor={vendor}"));
    }
    if ports.contains(&445) || ports.contains(&139) {
        hints.push("smb file sharing".into());
    }
    if ports.contains(&554) || ports.contains(&8009) {
        hints.push("rtsp/streaming (possible camera/NVR)".into());
    }
    if ports.contains(&9100) {
        hints.push("printer".into());
    }
    if ports.contains(&50050) || ports.contains(&50051) {
        hints.push("grpc service".into());
    }
    for probe in http {
        let hay = format!(
            "{} {}",
            probe.title.as_deref().unwrap_or_default(),
            probe.server.as_deref().unwrap_or_default()
        )
        .to_ascii_lowercase();
        for (needle, label) in [
            ("router", "router/gateway"),
            ("gateway", "router/gateway"),
            ("synology", "NAS (Synology)"),
            ("qnap", "NAS (QNAP)"),
            ("camera", "IP camera"),
            ("hikvision", "IP camera (Hikvision)"),
            ("dahua", "IP camera (Dahua)"),
            ("printer", "printer"),
            ("hp ", "printer (HP)"),
            ("nginx", "web server (nginx)"),
        ] {
            if hay.contains(needle) && !hints.iter().any(|h| h.contains(label)) {
                hints.push(label.into());
            }
        }
    }
    if hints.is_empty() {
        "unknown (see vendor/ports/title for clues)".into()
    } else {
        hints.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::service_name;

    #[test]
    fn extract_title_basic_and_whitespace() {
        assert_eq!(
            extract_title("<html><head><TITLE>My  Router</TITLE>"),
            Some("My Router".into())
        );
        assert_eq!(
            extract_title("<html><title  class=x>TP-Link</title></html>"),
            Some("TP-Link".into())
        );
        assert_eq!(extract_title("<html><body>no title</body>"), None);
        assert_eq!(extract_title("<title></title>"), None);
    }

    #[test]
    fn extract_title_skips_incomplete() {
        assert_eq!(extract_title("<title>unclosed"), None);
    }

    #[test]
    fn http_fingerprint_on_local_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = "HTTP/1.1 200 OK\r\nServer: Boa/0.94\r\nContent-Type: text/html\r\n\r\n<html><title>Home Gateway</title></html>";
            let _ = stream.write_all(response.as_bytes());
        });
        let probe = http_fingerprint(&format!("http://127.0.0.1:{port}/"), 2000).expect("probe");
        handle.join().unwrap();
        assert_eq!(probe.status, 200);
        assert_eq!(probe.server.as_deref(), Some("Boa/0.94"));
        assert_eq!(probe.title.as_deref(), Some("Home Gateway"));
    }

    #[test]
    fn guess_uses_vendor_and_ports() {
        let probe = HttpProbe {
            url: "http://x/".into(),
            status: 200,
            server: Some("Boa".into()),
            powered_by: None,
            title: Some("Hikvision-Digital-Technology".into()),
        };
        let guess = guess_device_type(Some("Espressif"), &[80, 554], std::slice::from_ref(&probe));
        assert!(guess.contains("Espressif"));
        assert!(guess.contains("rtsp"));
        assert!(guess.contains("camera"));

        let guess = guess_device_type(None, &[9100], &[]);
        assert!(guess.contains("printer"));
    }

    #[test]
    fn analyze_reports_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Hold the listener for the duration of the analysis.
        let report = analyze(
            IpAddr::from([127, 0, 0, 1]),
            Some(&[port]),
            500,
            0,
            false,
        )
        .unwrap();
        drop(listener);
        assert_eq!(report.ip.to_string(), "127.0.0.1");
        assert_eq!(report.open_ports[0].port, port);
        assert_eq!(report.open_ports[0].service, service_name(port).map(str::to_string));
    }
}
