//! Integration tests running the real `neton` binary (CLI surface).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;

use serde_json::Value;

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], stdin: Option<&str>) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_neton"))
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn neton");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(input.as_bytes())
            .expect("failed to write stdin");
    }
    let output = child.wait_with_output().expect("failed to wait for neton");
    Run {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn parse(result: &Run) -> Value {
    serde_json::from_str(result.stdout.trim())
        .unwrap_or_else(|err| panic!("stdout is not valid JSON ({err}): {}", result.stdout))
}

#[test]
fn help_exits_zero_and_lists_all_subcommands() {
    let result = run(&["--help"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    for name in [
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
        "serve",
    ] {
        assert!(result.stdout.contains(name), "help should mention '{name}'");
    }
    assert!(result.stdout.contains("--json"));
    assert!(result.stdout.contains("--pretty"));
    assert!(
        result.stdout.contains("--yes-i-have-permission"),
        "help must document the scan authorization flag"
    );
}

#[test]
fn info_outputs_expected_fields_as_compact_json() {
    let result = run(&["info"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert!(value["hostname"].is_string() || value["hostname"].is_null());
    assert!(value["os"].is_string() || value["os"].is_null());
    assert_eq!(value["arch"], std::env::consts::ARCH);
    // Compact (default) output must be a single JSON line.
    assert!(!result.stdout.trim().contains('\n'));
}

#[test]
fn info_accepts_json_and_pretty_flags() {
    let compact = run(&["info", "--json"], None);
    assert_eq!(compact.status, 0);
    parse(&compact);

    let pretty = run(&["info", "--pretty"], None);
    assert_eq!(pretty.status, 0);
    assert!(pretty.stdout.contains("\n  \""), "expected indented output");
    // Both formats carry the same data.
    let a = parse(&compact);
    let b = parse(&pretty);
    assert_eq!(a["arch"], b["arch"]);
}

#[test]
fn interfaces_lists_entries_with_expected_shape() {
    let result = run(&["interfaces"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    let entries = value.as_array().expect("interfaces must be an array");
    assert!(!entries.is_empty(), "a machine always has interfaces");
    for entry in entries {
        assert!(entry["name"].is_string());
        assert!(entry["ipv4"].is_array());
        assert!(entry["ipv6"].is_array());
        assert!(entry["mac"].is_string() || entry["mac"].is_null());
        assert!(entry["status"] == "up" || entry["status"] == "down");
        assert!(entry["loopback"].is_boolean());
    }
}

#[test]
fn dns_resolves_localhost() {
    let result = run(&["dns", "localhost"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["ok"], true);
    let ipv4 = value["ipv4"].as_array().expect("ipv4 array");
    assert!(
        ipv4.iter().any(|ip| ip == "127.0.0.1"),
        "localhost must resolve to 127.0.0.1, got {ipv4:?}"
    );
    assert!(value["elapsed_ms"].is_u64());
}

#[test]
fn dns_failure_is_data_not_crash() {
    let result = run(&["dns", "neton-nonexistent-host-for-tests.invalid"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["ok"], false);
    assert!(!value["error"].as_str().expect("error message").is_empty());
    assert_eq!(value["ipv4"].as_array().unwrap().len(), 0);
}

/// A loopback address (alias of 127.0.0.1) where nothing can listen on
/// privileged port 1, so a TCP connect is refused immediately and reliably
/// (no bind/drop race with other tests).
const REFUSED_TARGET: &str = "127.0.0.2:1";

#[test]
fn ping_succeeds_on_local_listener_and_fails_on_closed_port() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let ok = run(&["ping", "127.0.0.1", "-p", &port.to_string()], None);
    assert_eq!(ok.status, 0, "stderr: {}", ok.stderr);
    let value = parse(&ok);
    assert_eq!(value["ok"], true);
    assert_eq!(value["port"], port as u64);
    assert_eq!(value["ip"], "127.0.0.1");
    assert_eq!(value["error"], Value::Null);

    let host = REFUSED_TARGET.split(':').next().unwrap();
    let port = REFUSED_TARGET.split(':').nth(1).unwrap();
    let fail = run(&["ping", host, "-p", port, "--timeout-ms", "2000"], None);
    assert_eq!(
        fail.status, 0,
        "observation failures are data, exit must stay 0"
    );
    let value = parse(&fail);
    assert_eq!(value["ok"], false);
    assert!(value["error"].is_string());
}

#[test]
fn missing_required_argument_is_an_error() {
    let result = run(&["dns"], None);
    assert_ne!(result.status, 0, "dns without a host must fail");
    assert!(!result.stderr.is_empty());
    assert!(result.stdout.trim().is_empty(), "errors go to stderr only");
}

#[test]
fn piped_stdin_overrides_cli_arguments() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    // CLI points at an unroutable address; stdin must win and hit the listener.
    let input = format!(r#"{{"host": "127.0.0.1", "port": {port}}}"#);
    let result = run(&["ping", "192.0.2.1", "-p", "1"], Some(&input));
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(
        value["ok"], true,
        "stdin must override CLI args: {}",
        result.stdout
    );
    assert_eq!(value["port"], port as u64);
}

#[test]
fn piped_stdin_routes_action_without_subcommand() {
    let result = run(&[], Some(r#"{"action": "dns", "host": "localhost"}"#));
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["ok"], true);

    let aliased = run(&[], Some(r#"{"tool": "dns", "host": "localhost"}"#));
    assert_eq!(aliased.status, 0);
    assert_eq!(parse(&aliased)["ok"], true);
}

#[test]
fn piped_stdin_ports_with_pid_filter() {
    let input = format!(r#"{{"pid": {}}}"#, std::process::id());
    let result = run(&["ports"], Some(&input));
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert!(value.is_array());
}

#[test]
fn probe_reports_every_target_in_order() {
    let mut listeners = Vec::new();
    let mut open = Vec::new();
    for _ in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        open.push(listener.local_addr().expect("addr").port());
        listeners.push(listener);
    }
    // The second target is reliably refused (loopback alias, privileged port).
    let targets = format!(
        "127.0.0.1:{},127.0.0.2:1,127.0.0.1:{},127.0.0.1:{}",
        open[0], open[1], open[2]
    );
    let result = run(&["probe", &targets, "--timeout-ms", "2000"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["total"], 4);
    assert_eq!(value["open"], 3);
    // Concurrency defaults to 32 but is capped at the number of targets.
    assert_eq!(value["concurrency"], 4);
    let items = value["items"].as_array().expect("items array");
    assert_eq!(items.len(), 4);
    assert_eq!(items[0]["ok"], true);
    assert_eq!(
        items[1]["ok"], false,
        "refused target must be reported as not ok"
    );
    assert!(items[1]["error"].is_string());
    assert_eq!(items[2]["ok"], true);
    assert_eq!(items[3]["ok"], true);
}

#[test]
fn probe_concurrency_field_respects_requested_cap() {
    // TCP handshakes complete in the kernel backlog even before the server
    // accepts, so server-side connection overlap cannot measure the client
    // pool — the deterministic contract is the reported concurrency field
    // (capped by both the request and the target count) plus full coverage.
    let mut listeners = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..4 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        ports.push(listener.local_addr().expect("addr").port());
        listeners.push(listener);
    }
    let targets = ports
        .iter()
        .map(|p| format!("127.0.0.1:{p}"))
        .collect::<Vec<_>>()
        .join(",");

    let value = parse(&run(&["probe", &targets, "--concurrency", "2"], None));
    assert_eq!(value["concurrency"], 2);
    assert_eq!(value["open"], 4, "all listeners must answer");

    let value = parse(&run(&["probe", &targets, "--concurrency", "100"], None));
    assert_eq!(value["concurrency"], 4, "capped at target count");

    let value = parse(&run(&["probe", &targets], None));
    assert_eq!(
        value["concurrency"], 4,
        "default 32 is capped at target count"
    );
    assert_eq!(value["total"], 4);
}

#[test]
fn ports_lists_own_listener_with_pid_and_process() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let result = run(&["ports"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    let entries = value.as_array().expect("ports must be an array");
    assert!(!entries.is_empty(), "a machine always has some sockets");
    let own = entries
        .iter()
        .find(|entry| entry["proto"] == "tcp" && entry["local_port"].as_u64() == Some(port as u64))
        .unwrap_or_else(|| panic!("own listener on {port} not found in ports output"));
    assert_eq!(own["state"], "Listen");
    assert_eq!(own["pid"].as_u64(), Some(std::process::id() as u64));
    assert!(own["process"].is_string(), "process name must be present");
}

#[test]
fn http_reports_status_body_and_redacts_set_cookie() {
    const SECRET: &str = "session=super-secret-cookie-1234567890";
    const BODY: &str = "hello from neton test";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: {SECRET}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                BODY.len(),
                BODY
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let result = run(&["http", &format!("http://127.0.0.1:{port}/")], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["ok"], true);
    assert_eq!(value["status"], 200);
    assert_eq!(value["body"], BODY);
    let cookie = &value["headers"]["set-cookie"];
    assert_eq!(
        cookie[0]["redacted"], true,
        "set-cookie must be redacted: {cookie}"
    );
    assert_eq!(cookie[0]["length"], SECRET.len());
    assert!(
        !value.to_string().contains("super-secret"),
        "cookie value must never leak into the output"
    );
}

// ------------------------------------------------------------ arp / scans ----

#[test]
fn arp_outputs_entry_array_with_vendor_field() {
    let result = run(&["arp"], None);
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    let entries = value.as_array().expect("arp must be an array");
    for entry in entries {
        assert!(entry["ip"].is_string());
        assert!(entry["mac"].is_string() || entry["mac"].is_null());
        assert!(entry["vendor"].is_string() || entry["vendor"].is_null());
        assert!(entry["interface"].is_string() || entry["interface"].is_null());
        assert!(entry["state"].is_string() || entry["state"].is_null());
    }
}

#[test]
fn scan_commands_require_explicit_authorization() {
    for (name, args) in [
        ("netscan", vec!["netscan", "127.0.0.0/30"]),
        ("portscan", vec!["portscan", "127.0.0.1", "--ports", "1"]),
        ("device", vec!["device", "127.0.0.1"]),
    ] {
        let result = run(&args, None);
        assert_eq!(result.status, 2, "{name} without permission must exit 2");
        assert!(result.stderr.contains("--yes-i-have-permission"));
        assert!(
            result.stdout.trim().is_empty(),
            "{name} must not emit data without permission"
        );
    }

    // Piped-stdin action routing is gated the same way.
    let result = run(
        &[],
        Some(r#"{"action": "portscan", "target": "127.0.0.1", "ports": "1"}"#),
    );
    assert_eq!(result.status, 2, "stdin-routed scans must also be gated");
}

#[test]
fn portscan_finds_local_listener_with_permission() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let result = run(
        &[
            "portscan",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--timeout-ms",
            "500",
            "--yes-i-have-permission",
        ],
        None,
    );
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["target"], "127.0.0.1");
    assert_eq!(value["ip"], "127.0.0.1");
    assert_eq!(value["ports_scanned"], 1);
    assert_eq!(value["open_count"], 1);
    assert_eq!(value["open"][0]["port"], port as u64);
    assert!(value["elapsed_ms"].is_u64());
}

#[test]
fn portscan_reports_zero_open_ports_as_data() {
    let result = run(
        &[
            "portscan",
            "127.0.0.2",
            "--ports",
            "1",
            "--timeout-ms",
            "500",
            "--yes-i-have-permission",
        ],
        None,
    );
    assert_eq!(result.status, 0, "empty scan is data, not an error");
    let value = parse(&result);
    assert_eq!(value["open_count"], 0);
    assert_eq!(value["open"].as_array().unwrap().len(), 0);
}

#[test]
fn device_analyzes_local_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let result = run(
        &[
            "device",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--timeout-ms",
            "500",
            "--http-max",
            "0",
            "--no-rdns",
            "--yes-i-have-permission",
        ],
        None,
    );
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["ip"], "127.0.0.1");
    assert!(value["open_ports"].as_array().expect("ports").len() >= 1);
    assert!(value["guess"].is_string());
    assert!(value["http"].as_array().expect("http probes").is_empty());
}

#[test]
fn netscan_discovers_loopback_device() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let result = run(
        &[
            "netscan",
            "127.0.0.0/30",
            "--ports",
            &port.to_string(),
            "--timeout-ms",
            "300",
            "--no-rdns",
            "--yes-i-have-permission",
        ],
        None,
    );
    assert_eq!(result.status, 0, "stderr: {}", result.stderr);
    let value = parse(&result);
    assert_eq!(value["hosts_total"], 4);
    assert!(value["devices_found"].as_u64().expect("count") >= 1);
    let devices = value["devices"].as_array().expect("devices");
    let hit = devices
        .iter()
        .find(|d| d["ip"] == "127.0.0.1")
        .expect("loopback device must be discovered");
    assert_eq!(hit["open_ports"][0]["port"], port as u64);
    assert!(
        hit["via"].as_array().unwrap().iter().any(|v| v == "tcp"),
        "tcp discovery path must be reported"
    );
}

#[test]
fn scan_commands_reject_bad_input() {
    // Invalid CIDR is an error even with permission.
    let result = run(&["netscan", "not-a-cidr", "--yes-i-have-permission"], None);
    assert_ne!(result.status, 0);
    assert!(result.stderr.contains("invalid"));

    // Oversized CIDR is rejected before any packet is sent.
    let result = run(&["netscan", "10.0.0.0/8", "--yes-i-have-permission"], None);
    assert_ne!(result.status, 0);
    assert!(result.stderr.contains("limit"));

    // Bad port spec.
    let result = run(
        &["portscan", "127.0.0.1", "--ports", "99999", "--yes-i-have-permission"],
        None,
    );
    assert_ne!(result.status, 0);

    // Invalid IP for device.
    let result = run(&["device", "not-an-ip", "--yes-i-have-permission"], None);
    assert_ne!(result.status, 0);
    assert!(result.stderr.contains("IP"));
}
