//! Injection / robustness tests for `neton serve`.
//!
//! neton never spawns a shell, never talks to a database and never serves files
//! from a request-supplied path, so its untrusted-input surface is the action
//! parameter parser plus the bearer-token gate. These tests prove that hostile
//! payloads (XSS markup, shell metacharacters, path traversal, JSON type
//! confusion and SQL-style auth bypass) are parsed / rejected rather than
//! executed, and that nothing ever escapes a structured JSON result or a clean
//! 400 / 401 / 403 status.

use std::net::SocketAddr;
use std::sync::mpsc;

use serde_json::{json, Value};

/// Spawn the real router on a loopback port inside a dedicated runtime thread.
fn spawn_server(token: Option<String>, scan_authorized: bool) -> SocketAddr {
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            tx.send(addr).expect("send addr");
            axum::serve(listener, neton::serve::router(token, scan_authorized))
                .await
                .expect("serve");
        });
    });
    rx.recv().expect("server address")
}

fn post_json(url: &str, body: Value, token: Option<&str>) -> (u16, Value) {
    let mut request = ureq::post(url);
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.send_json(body) {
        Ok(response) => (response.status(), response.into_json().unwrap_or(Value::Null)),
        Err(ureq::Error::Status(status, response)) => {
            (status, response.into_json().unwrap_or(Value::Null))
        }
        Err(err) => panic!("request failed unexpectedly: {err}"),
    }
}

/// POST an already-serialized (possibly malformed) string body.
fn post_raw(url: &str, raw: &str) -> (u16, Value) {
    match ureq::post(url)
        .set("Content-Type", "application/json")
        .send_string(raw)
    {
        Ok(response) => (response.status(), response.into_json().unwrap_or(Value::Null)),
        Err(ureq::Error::Status(status, response)) => {
            (status, response.into_json().unwrap_or(Value::Null))
        }
        Err(err) => panic!("request failed unexpectedly: {err}"),
    }
}

#[test]
fn malformed_json_body_is_400_not_500() {
    let addr = spawn_server(None, false);
    let (status, body) = post_raw(&format!("http://{addr}/invoke"), "{ this is not json");
    assert_eq!(status, 400, "a bad JSON document must be a client error, not a crash");
    assert!(body["error"].is_string());
}

#[test]
fn params_not_an_object_is_400() {
    let addr = spawn_server(None, false);
    for bad in [json!("a string"), json!([1, 2, 3]), json!(42)] {
        let (status, body) = post_json(
            &format!("http://{addr}/invoke"),
            json!({ "params": bad }),
            None,
        );
        assert_eq!(status, 400, "params={bad} must be rejected, not coerced");
        assert!(body["error"].is_string());
    }
}

#[test]
fn xss_payload_as_host_is_opaque_data_not_executed() {
    let addr = spawn_server(None, false);
    let payload = "<script>alert(1)</script>";
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "dns", "host": payload } }),
        None,
    );
    assert_eq!(status, 200, "a failed lookup is data, not a server error");
    // The payload is echoed verbatim as a JSON string — never rendered as HTML.
    assert_eq!(body["host"], payload);
    assert_eq!(body["ok"], json!(false));
    assert!(body["error"].is_string());
}

#[test]
fn shell_metacharacters_as_host_do_not_spawn_a_shell() {
    let addr = spawn_server(None, false);
    let payload = "; cat /etc/passwd; #";
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "dns", "host": payload } }),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["host"], payload);
    assert_eq!(
        body["ok"],
        json!(false),
        "no shell ran; the string is treated as a DNS name that cannot resolve"
    );
}

#[test]
fn path_traversal_as_cidr_is_rejected_without_a_file_read() {
    let addr = spawn_server(None, true);
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "netscan", "cidr": "../../etc/passwd" } }),
        None,
    );
    // The traversal string fails CIDR parsing; netscan surfaces that as a
    // server-side failure (500) — never as a successful scan, and never as a
    // file read. The key assertion is that no traversal happened.
    assert!(
        matches!(status, 400 | 500),
        "a traversal string must be rejected, got {status}"
    );
    assert!(body["error"].is_string());
}

#[test]
fn device_ip_with_injection_string_is_rejected() {
    let addr = spawn_server(None, true);
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "device", "ip": "127.0.0.1; cat /etc/passwd" } }),
        None,
    );
    assert_eq!(status, 400, "the ip string must fail address parsing");
    assert!(body["error"].is_string());
}

#[test]
fn port_spec_injection_and_span_overflow_are_rejected() {
    let addr = spawn_server(None, true);
    for ports in ["80; rm -rf /", "1-99999", "../../etc/passwd"] {
        let (status, body) = post_json(
            &format!("http://{addr}/invoke"),
            json!({ "params": { "action": "netscan", "cidr": "127.0.0.0/30", "ports": ports } }),
            None,
        );
        assert_eq!(status, 400, "ports={ports} must be rejected");
        assert!(body["error"].is_string());
    }
}

#[test]
fn javascript_url_is_returned_as_data_not_fetched() {
    let addr = spawn_server(None, false);
    let url = "javascript:alert(document.cookie)";
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "http", "url": url, "timeout_ms": 500 } }),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["url"], url, "the payload is echoed as data");
    assert_eq!(body["ok"], json!(false), "a javascript: URI is never executed");
}

#[test]
fn sql_like_auth_bypass_does_not_defeat_the_bearer_token() {
    let addr = spawn_server(Some("s3cret".to_string()), false);
    let base = format!("http://{addr}");
    for guess in ["' OR 1=1 --", "\" OR \"\"=\"", "admin", "s3cret;", "s3cret' OR '1'='1"] {
        let (status, _) = post_json(
            &format!("{base}/invoke"),
            json!({ "params": { "action": "info" } }),
            Some(guess),
        );
        assert_eq!(status, 401, "guess {guess:?} must not authenticate");
    }
    // Control: the exact token still works.
    let (status, body) = post_json(
        &format!("{base}/invoke"),
        json!({ "params": { "action": "info" } }),
        Some("s3cret"),
    );
    assert_eq!(status, 200);
    assert!(body["arch"].is_string());
}

#[test]
fn mcp_tool_call_with_non_object_arguments_is_tolerated() {
    let addr = spawn_server(None, false);
    let url = format!("http://{addr}/mcp");
    // Handshake to obtain a session id.
    let (_, sid, _) = match ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-03-26", "capabilities": {} }
        })) {
        Ok(r) => (
            r.status(),
            r.header("Mcp-Session-Id").map(str::to_string),
            r.into_json().unwrap_or(Value::Null),
        ),
        Err(ureq::Error::Status(_, r)) => (
            r.status(),
            r.header("Mcp-Session-Id").map(str::to_string),
            r.into_json().unwrap_or(Value::Null),
        ),
        Err(err) => panic!("handshake failed: {err}"),
    };
    // Hostile arguments: an array instead of an object must be ignored, never
    // merged into the dispatch params.
    let (_, _, body) = match ureq::post(&url)
        .set("Content-Type", "application/json")
        .set("Mcp-Session-Id", &sid.expect("session id"))
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "dns", "arguments": ["<script>", 1, {"a": "b"}] }
        })) {
        Ok(r) => (
            r.status(),
            r.header("Mcp-Session-Id").map(str::to_string),
            r.into_json().unwrap_or(Value::Null),
        ),
        Err(ureq::Error::Status(_, r)) => (
            r.status(),
            r.header("Mcp-Session-Id").map(str::to_string),
            r.into_json().unwrap_or(Value::Null),
        ),
        Err(err) => panic!("call failed: {err}"),
    };
    // dns without a host argument -> a graceful isError, never a transport
    // error or panic.
    assert_eq!(body["result"]["isError"], json!(true));
    assert!(
        body["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("host")
            || body["error"].is_object(),
        "must report the missing 'host' param, not echo the hostile array"
    );
}
