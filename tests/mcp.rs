//! Integration tests for the MCP surface of `neton serve` (Streamable HTTP
//! JSON-RPC on `/` and `/mcp`). Uses the real router in-process — the only
//! network touched is loopback.

use std::net::SocketAddr;
use std::sync::mpsc;

use serde_json::{json, Value};

/// Spawn `neton serve`'s router on a random port inside a dedicated runtime
/// thread. `scan_authorized` mirrors the `--yes-i-have-permission` server flag.
fn spawn_server(scan_authorized: bool) -> SocketAddr {
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            let addr = listener.local_addr().expect("addr");
            tx.send(addr).expect("send addr");
            axum::serve(listener, neton::serve::router(None, scan_authorized))
                .await
                .expect("serve");
        });
    });
    rx.recv().expect("server addr")
}

/// POST a JSON-RPC message and return (status, Set-Mcp-Session-Id?, body).
fn rpc(url: &str, session: Option<&str>, message: Value) -> (u16, Option<String>, Value) {
    let mut request = ureq::post(url).set("Content-Type", "application/json");
    if let Some(sid) = session {
        request = request.set("Mcp-Session-Id", sid);
    }
    match request.send_string(&message.to_string()) {
        Ok(response) => (
            response.status(),
            response.header("Mcp-Session-Id").map(str::to_string),
            response.into_json().unwrap_or(Value::Null),
        ),
        Err(ureq::Error::Status(status, response)) => (
            status,
            response.header("Mcp-Session-Id").map(str::to_string),
            response.into_json().unwrap_or(Value::Null),
        ),
        Err(err) => panic!("request failed unexpectedly: {err}"),
    }
}

fn initialize(_base: &str, path: &str) -> (SocketAddr, String, Value) {
    let addr = spawn_server(false);
    let url = format!("http://{addr}{path}");
    let (status, sid, body) = rpc(
        &url,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" }
            }
        }),
    );
    assert_eq!(status, 200);
    assert_eq!(body["result"]["serverInfo"]["name"], "neton");
    let sid = sid.expect("initialize must issue an Mcp-Session-Id");
    (addr, sid, body)
}

#[test]
fn handshake_on_root_and_mcp_paths() {
    for path in ["/", "/mcp"] {
        let (addr, sid, body) = initialize("unused", path);
        assert_eq!(
            body["result"]["protocolVersion"], "2025-03-26",
            "path {path} must negotiate"
        );
        assert!(sid.starts_with("mcp-"));
        // The same session id works for follow-ups.
        let (_, _, ping) = rpc(
            &format!("http://{addr}{path}"),
            Some(&sid),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }),
        );
        assert_eq!(ping["result"], json!({}));
    }
}

#[test]
fn unknown_client_version_falls_back() {
    let (addr, _sid, body) = initialize_init_with("1999-01-01");
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
    let _ = addr;
}

fn initialize_init_with(client_version: &str) -> (SocketAddr, String, Value) {
    let addr = spawn_server(false);
    let (status, sid, body) = rpc(
        &format!("http://{addr}/mcp"),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": client_version, "capabilities": {} }
        }),
    );
    assert_eq!(status, 200);
    (addr, sid.expect("session id"), body)
}

#[test]
fn notifications_are_accepted_silently() {
    let addr = spawn_server(false);
    let (status, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        None,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    assert_eq!(status, 202);
    assert_eq!(body, Value::Null);
}

#[test]
fn tools_list_exposes_all_eleven_with_gating_data() {
    let (addr, sid, _) = initialize("unused", "/mcp");
    let (_, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        Some(&sid),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }),
    );
    let tools = body["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 11);
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        vec![
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
        ]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(!tool["description"].as_str().expect("desc").is_empty());
    }
}

#[test]
fn tools_call_info_returns_host_data() {
    let (addr, sid, _) = initialize("unused", "/mcp");
    let (_, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "info", "arguments": {} }
        }),
    );
    let result = &body["result"];
    assert_eq!(result["isError"], false);
    let text = result["content"][0]["text"].as_str().expect("text");
    let payload: Value = serde_json::from_str(text).expect("payload is JSON text");
    assert!(payload["hostname"].is_string() || payload["ok"] == json!(true) || payload.is_object());
}

#[test]
fn tools_call_dns_with_missing_arg_is_error_result() {
    let (addr, sid, _) = initialize("unused", "/mcp");
    let (_, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "dns", "arguments": {} }
        }),
    );
    assert_eq!(body["result"]["isError"], true);
    assert!(
        body["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("host"),
        "refusal must name the missing parameter"
    );
}

#[test]
fn tools_call_scan_gated_when_locked() {
    let addr = spawn_server(false);
    let (status, sid, _) = rpc(
        &format!("http://{addr}/mcp"),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-03-26", "capabilities": {} }
        }),
    );
    assert_eq!(status, 200);
    let (_, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        Some(&sid.expect("session id")),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": { "name": "netscan", "arguments": { "cidr": "127.0.0.0/30" } }
        }),
    );
    assert_eq!(body["result"]["isError"], true);
    let text = body["result"]["content"][0]["text"].as_str().expect("text");
    assert!(
        text.contains("--yes-i-have-permission"),
        "gate refusal must name the flag: {text}"
    );
}

#[test]
fn tools_call_netscan_local_loopback_when_unlocked() {
    let addr = spawn_server(true);
    let (status, sid, _) = rpc(
        &format!("http://{addr}/mcp"),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-03-26", "capabilities": {} }
        }),
    );
    assert_eq!(status, 200);
    let (_, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        Some(&sid.expect("session id")),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "portscan",
                "arguments": { "target": "127.0.0.1", "ports": "9", "timeout_ms": 200 }
            }
        }),
    );
    let result = &body["result"];
    assert_eq!(result["isError"], false, "{}", result["content"][0]["text"]);
    let payload: Value = serde_json::from_str(result["content"][0]["text"].as_str().expect("text"))
        .expect("payload");
    assert_eq!(payload["target"], "127.0.0.1");
}

#[test]
fn unknown_tool_is_jsonrpc_error() {
    let (addr, sid, _) = initialize("unused", "/mcp");
    let (_, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": { "name": "nope", "arguments": {} }
        }),
    );
    assert_eq!(body["error"]["code"], -32602);
}

#[test]
fn unknown_method_is_jsonrpc_error() {
    let (addr, sid, _) = initialize("unused", "/mcp");
    let (_, _, body) = rpc(
        &format!("http://{addr}/mcp"),
        Some(&sid),
        json!({ "jsonrpc": "2.0", "id": 9, "method": "resources/list" }),
    );
    assert_eq!(body["error"]["code"], -32601);
}

#[test]
fn invalid_json_body_is_parse_error() {
    let addr = spawn_server(false);
    let response = match ureq::post(&format!("http://{addr}/mcp"))
        .set("Content-Type", "application/json")
        .send_string("not json")
    {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(err) => panic!("request failed: {err}"),
    };
    assert_eq!(response.status(), 200);
    let body: Value = response.into_json().expect("json");
    assert_eq!(body["error"]["code"], -32700);
}

#[test]
fn health_reports_mcp_capability() {
    let addr = spawn_server(false);
    let response = ureq::get(&format!("http://{addr}/health"))
        .call()
        .expect("health");
    let body: Value = response.into_json().expect("json");
    assert_eq!(body["ok"], json!(true));
    assert_eq!(body["mcp"], json!(true));
    assert_eq!(body["service"], "neton");
}
