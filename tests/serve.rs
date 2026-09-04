//! Integration tests for `neton serve` (BIT Remote protocol over HTTP).

use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;

use serde_json::{json, Value};

/// Spawn `neton serve` on a random port inside a dedicated runtime thread.
fn spawn_server(token: Option<String>) -> SocketAddr {
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
            axum::serve(listener, neton::serve::router(token))
                .await
                .expect("serve");
        });
    });
    rx.recv().expect("server address")
}

/// POST a JSON body, returning (status, parsed body) for any status code.
fn post_json(url: &str, body: Value, token: Option<&str>) -> (u16, Value) {
    let mut request = ureq::post(url);
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.send_json(body) {
        Ok(response) => {
            let status = response.status();
            (status, response.into_json().expect("json body"))
        }
        Err(ureq::Error::Status(status, response)) => {
            let value = response.into_json().unwrap_or(Value::Null);
            (status, value)
        }
        Err(err) => panic!("request failed unexpectedly: {err}"),
    }
}

fn get(url: &str, token: Option<&str>) -> (u16, Value) {
    let mut request = ureq::get(url);
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.call() {
        Ok(response) => {
            let status = response.status();
            (status, response.into_json().expect("json body"))
        }
        Err(ureq::Error::Status(status, response)) => {
            let value = response.into_json().unwrap_or(Value::Null);
            (status, value)
        }
        Err(err) => panic!("request failed unexpectedly: {err}"),
    }
}

#[test]
fn health_returns_ok() {
    let addr = spawn_server(None);
    let (status, body) = get(&format!("http://{addr}/health"), None);
    assert_eq!(status, 200);
    assert_eq!(body["ok"], json!(true));
}

#[test]
fn invoke_actions_lists_all_actions() {
    let addr = spawn_server(None);
    let (status, body) = get(&format!("http://{addr}/invoke-actions"), None);
    assert_eq!(status, 200);
    let actions = body["actions"].as_array().expect("actions array");
    let names: Vec<&str> = actions.iter().filter_map(Value::as_str).collect();
    for expected in [
        "info",
        "interfaces",
        "ports",
        "dns",
        "ping",
        "probe",
        "http",
    ] {
        assert!(names.contains(&expected), "missing action '{expected}'");
    }
    assert_eq!(names.len(), 7);
}

#[test]
fn invoke_ping_against_local_listener() {
    let addr = spawn_server(None);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({
            "tool_id": "neton-remote",
            "tool": "neton_remote",
            "invoked_by": "test",
            "params": { "action": "ping", "host": "127.0.0.1", "port": port }
        }),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["ok"], json!(true));
    assert_eq!(body["port"], port as u64);
    assert_eq!(body["ip"], "127.0.0.1");
}

#[test]
fn invoke_info_and_interfaces_return_data() {
    let addr = spawn_server(None);
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "info" } }),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["arch"], std::env::consts::ARCH);

    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "interfaces" } }),
        None,
    );
    assert_eq!(status, 200);
    assert!(!body.as_array().expect("interfaces array").is_empty());
}

#[test]
fn invoke_unknown_action_is_400() {
    let addr = spawn_server(None);
    let (status, body) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "nope" } }),
        None,
    );
    assert_eq!(status, 400);
    assert!(body["error"]
        .as_str()
        .expect("error")
        .contains("unknown action"));
}

#[test]
fn invoke_without_params_or_action_is_400() {
    let addr = spawn_server(None);
    let (status, body) = post_json(&format!("http://{addr}/invoke"), json!({}), None);
    assert_eq!(status, 400);
    assert!(body["error"].is_string());

    let (status, _) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "host": "localhost" } }),
        None,
    );
    assert_eq!(status, 400, "params without action must be rejected");

    let (status, _) = post_json(
        &format!("http://{addr}/invoke"),
        json!({ "params": { "action": "dns" } }),
        None,
    );
    assert_eq!(status, 400, "dns without host must be rejected");
}

#[test]
fn token_protects_everything_except_health() {
    let addr = spawn_server(Some("s3cret".into()));
    let base = format!("http://{addr}");

    // /health stays open.
    let (status, body) = get(&format!("{base}/health"), None);
    assert_eq!(status, 200);
    assert_eq!(body["ok"], json!(true));

    // /invoke-actions requires the token.
    let (status, _) = get(&format!("{base}/invoke-actions"), None);
    assert_eq!(status, 401);
    let (status, _) = get(&format!("{base}/invoke-actions"), Some("wrong"));
    assert_eq!(status, 401);
    let (status, _) = get(&format!("{base}/invoke-actions"), Some("s3cret"));
    assert_eq!(status, 200);

    // /invoke requires the token.
    let (status, _) = post_json(
        &format!("{base}/invoke"),
        json!({ "params": { "action": "info" } }),
        None,
    );
    assert_eq!(status, 401);
    let (status, _) = post_json(
        &format!("{base}/invoke"),
        json!({ "params": { "action": "info" } }),
        Some("wrong"),
    );
    assert_eq!(status, 401);
    let (status, body) = post_json(
        &format!("{base}/invoke"),
        json!({ "params": { "action": "info" } }),
        Some("s3cret"),
    );
    assert_eq!(status, 200);
    assert!(body["arch"].is_string());
}
