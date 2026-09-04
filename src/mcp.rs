//! MCP (Model Context Protocol) server over Streamable HTTP — hand-rolled
//! JSON-RPC 2.0 on axum, wire-compatible with BIT's MCP client (the same
//! contract SECFORGE and PANOPTES speak). Tool calls route into neton's own
//! action dispatch, so the MCP surface and `POST /invoke` always agree.
//!
//! Contract (verified against BIT's client):
//! - `initialize` → result `{protocolVersion, capabilities:{tools:{listChanged:false}}, serverInfo}`
//!   plus an `Mcp-Session-Id` response header (echoed back by clients).
//! - `notifications/*` (or any id-less message) → HTTP 202, empty body.
//! - `tools/list` → `{tools:[{name, description, inputSchema}]}` (single page).
//! - `tools/call` → `{content:[{type:"text", text:<json string>}], isError}` —
//!   failures are 200 + `isError:true`, never transport errors.
//! - unknown method → JSON-RPC error -32601; `ping` → empty result.
//!
//! Sessions are issued for spec compliance but not tracked server-side: every
//! request is independent (no server-side session state to expire).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};

use crate::dispatch::{self, DispatchError};

/// Protocol versions we can speak; we echo the client's choice when possible.
const MCP_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

/// Server-side cap for one tool call (network actions carry their own,
/// smaller timeouts; scans may legitimately take longer than a client would
/// wait — the client-side timeout governs what the agent sees).
const TOOL_CALL_CAP: Duration = Duration::from_secs(30);

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// One neton capability exposed over MCP (mirrors one action 1:1).
pub struct ToolDef {
    /// MCP tool name = the action name.
    pub name: &'static str,
    /// English description surfaced in `tools/list`.
    pub description: &'static str,
    /// JSON Schema for the `arguments` object.
    pub input_schema: Value,
    /// Requires the server to be started with `--yes-i-have-permission`.
    pub scan_gated: bool,
}

/// Build a JSON-Schema object from `(name, type, description, required)` tuples.
fn schema(fields: &[(&str, &str, &str, bool)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, ty, desc, req) in fields {
        properties.insert(
            (*name).to_string(),
            json!({ "type": ty, "description": desc }),
        );
        if *req {
            required.push(json!(name));
        }
    }
    let mut schema = json!({ "type": "object", "properties": properties });
    if !required.is_empty() {
        schema["required"] = Value::Array(required);
    }
    schema
}

/// All tools neton exposes, in stable order. Gated tools stay listed — the
/// gate is enforced at call time so the model learns how to request
/// authorization from the refusal text.
pub fn tools() -> &'static [ToolDef] {
    static TOOLS: std::sync::OnceLock<Vec<ToolDef>> = std::sync::OnceLock::new();
    TOOLS.get_or_init(|| {
        vec![
            ToolDef {
                name: "info",
                description: "Host overview: hostname, OS, architecture, default outbound IP.",
                input_schema: schema(&[]),
                scan_gated: false,
            },
            ToolDef {
                name: "interfaces",
                description: "Network interfaces: name, IPv4/IPv6, MAC, up/down status.",
                input_schema: schema(&[]),
                scan_gated: false,
            },
            ToolDef {
                name: "ports",
                description: "Listening TCP sockets + bound UDP sockets with owning pid and \
                              process name.",
                input_schema: schema(&[(
                    "pid",
                    "integer",
                    "Only sockets owned by this pid",
                    false,
                )]),
                scan_gated: false,
            },
            ToolDef {
                name: "dns",
                description: "System resolver lookup returning IPv4/IPv6 arrays and elapsed ms.",
                input_schema: schema(&[("host", "string", "Hostname to resolve", true)]),
                scan_gated: false,
            },
            ToolDef {
                name: "ping",
                description: "TCP connect probe (zero ICMP): host, port and timeout in, latency \
                              and error in.",
                input_schema: schema(&[
                    ("host", "string", "Host to probe", true),
                    ("port", "integer", "TCP port (default 443)", false),
                    (
                        "timeout_ms",
                        "integer",
                        "Connect timeout in ms (default 2000)",
                        false,
                    ),
                ]),
                scan_gated: false,
            },
            ToolDef {
                name: "probe",
                description: "Probe many HOST:PORT targets concurrently; returns per-target \
                              reachability and latency.",
                input_schema: schema(&[
                    (
                        "targets",
                        "array",
                        "Array of \"host:port\" strings (a single comma-separated string also \
                         works)",
                        true,
                    ),
                    (
                        "concurrency",
                        "integer",
                        "Parallel connects (default 32)",
                        false,
                    ),
                    (
                        "timeout_ms",
                        "integer",
                        "Per-target connect timeout in ms (default 2000)",
                        false,
                    ),
                ]),
                scan_gated: false,
            },
            ToolDef {
                name: "http",
                description: "HTTP GET/POST summary: status, latency, trimmed body.",
                input_schema: schema(&[
                    ("url", "string", "URL to request", true),
                    ("method", "string", "HTTP method (default GET)", false),
                    (
                        "timeout_ms",
                        "integer",
                        "Request timeout in ms (default 5000)",
                        false,
                    ),
                    (
                        "body_max",
                        "integer",
                        "Maximum body characters kept (default 500)",
                        false,
                    ),
                ]),
                scan_gated: false,
            },
            ToolDef {
                name: "arp",
                description: "Read the OS ARP/neighbor table (no traffic sent).",
                input_schema: schema(&[]),
                scan_gated: false,
            },
            ToolDef {
                name: "netscan",
                description: "Discover live hosts in a CIDR by TCP-connecting common ports \
                              (optional reverse DNS). Only scan networks you own or are \
                              authorized to test.",
                input_schema: schema(&[
                    ("cidr", "string", "Network range, e.g. 192.168.1.0/24", true),
                    (
                        "ports",
                        "string",
                        "Port spec: \"80,443\" or \"1-1024\" (default 22,80,443,445,3389,8080)",
                        false,
                    ),
                    (
                        "concurrency",
                        "integer",
                        "Parallel connects (default 128)",
                        false,
                    ),
                    (
                        "timeout_ms",
                        "integer",
                        "Per-connect timeout in ms (default 400)",
                        false,
                    ),
                    ("no_rdns", "boolean", "Skip reverse DNS lookups", false),
                ]),
                scan_gated: true,
            },
            ToolDef {
                name: "portscan",
                description: "TCP-connect port scan of one target with open/closed results. \
                              Only scan hosts you own or are authorized to test.",
                input_schema: schema(&[
                    ("target", "string", "Host or IP to scan", true),
                    (
                        "ports",
                        "string",
                        "Port spec: \"80,443\" or \"1-1024\" (default: common ports)",
                        false,
                    ),
                    (
                        "concurrency",
                        "integer",
                        "Parallel connects (default 256)",
                        false,
                    ),
                    (
                        "timeout_ms",
                        "integer",
                        "Per-connect timeout in ms (default 400)",
                        false,
                    ),
                ]),
                scan_gated: true,
            },
            ToolDef {
                name: "device",
                description: "Fingerprint one device: reverse DNS, ARP entry, open ports, \
                              service guesses from open-port signatures. Only scan devices \
                              you own or are authorized to test.",
                input_schema: schema(&[
                    ("ip", "string", "IPv4 or IPv6 address", true),
                    (
                        "ports",
                        "string",
                        "Optional port spec (default: common ports)",
                        false,
                    ),
                    (
                        "timeout_ms",
                        "integer",
                        "Per-connect timeout in ms (default 1000)",
                        false,
                    ),
                    (
                        "http_max",
                        "integer",
                        "HTTP banner characters to fetch (default 500)",
                        false,
                    ),
                    ("no_rdns", "boolean", "Skip reverse DNS lookups", false),
                ]),
                scan_gated: true,
            },
        ]
    })
}

struct McpState {
    scan_authorized: bool,
}

/// Protocol versions we can speak; we echo the client's choice when possible.
fn negotiate_version(client: &str) -> &'static str {
    MCP_VERSIONS
        .iter()
        .find(|v| **v == client)
        .copied()
        .unwrap_or(MCP_VERSIONS[MCP_VERSIONS.len() - 1])
}

/// Mirror BIT's `gen_mcp_session_id`: monotonic, unique per process.
fn gen_session_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("mcp-{nanos:x}-{:x}-{seq:x}", std::process::id())
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn json_response(status: StatusCode, body: Option<Value>, session: Option<&str>) -> Response {
    use axum::response::IntoResponse;
    let mut builder = Response::builder().status(status);
    if let Some(sid) = session {
        builder = builder.header("Mcp-Session-Id", sid);
    }
    match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(axum::body::Body::from(v.to_string()))
            .expect("static response"),
        None => builder
            .body(axum::body::Body::empty())
            .expect("static response"),
    }
    .into_response()
}

/// MCP JSON-RPC entry point, mounted on both `/` (BIT discovery probes the root)
/// and `/mcp` (the canonical Streamable HTTP path).
async fn rpc_entry(State(state): State<Arc<McpState>>, body: Bytes) -> Response {
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode::OK,
                Some(rpc_err(Value::Null, -32700, &format!("parse error: {e}"))),
                None,
            );
        }
    };

    let method = msg
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string();
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let is_notification = msg.get("id").is_none() || method.starts_with("notifications/");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    if is_notification {
        return json_response(StatusCode::ACCEPTED, None, None);
    }

    match method.as_str() {
        "initialize" => {
            let client_ver = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let session = gen_session_id();
            let result = json!({
                "protocolVersion": negotiate_version(client_ver),
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": "neton",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            });
            json_response(StatusCode::OK, Some(rpc_ok(id, result)), Some(&session))
        }
        "ping" => json_response(StatusCode::OK, Some(rpc_ok(id, json!({}))), None),
        "tools/list" => {
            let tools: Vec<Value> = tools()
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    })
                })
                .collect();
            json_response(
                StatusCode::OK,
                Some(rpc_ok(id, json!({ "tools": tools }))),
                None,
            )
        }
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let Some(_tool) = tools().iter().find(|t| t.name == name) else {
                return json_response(
                    StatusCode::OK,
                    Some(rpc_err(id, -32602, &format!("tool not found: '{name}'"))),
                    None,
                );
            };
            let scan_authorized = state.scan_authorized;
            // Route into the same funnel as `POST /invoke`: the MCP tool name
            // is the action name, the MCP arguments are the action parameters.
            let call = match args {
                Value::Object(mut map) => {
                    map.insert("action".into(), json!(name));
                    Value::Object(map)
                }
                _ => json!({ "action": name }),
            };
            let outcome = tokio::time::timeout(
                TOOL_CALL_CAP,
                tokio::task::spawn_blocking(move || {
                    dispatch::dispatch_with(&call, scan_authorized).map_err(dispatch_error_text)
                }),
            )
            .await;
            let (text, is_error) = match outcome {
                Ok(Ok(Ok(value))) => (value.to_string(), false),
                Ok(Ok(Err(message))) => (message, true),
                Ok(Err(join)) => (format!("tool task failed: {join}"), true),
                Err(_) => (
                    format!("tool '{name}' timed out after {}s", TOOL_CALL_CAP.as_secs()),
                    true,
                ),
            };
            json_response(
                StatusCode::OK,
                Some(rpc_ok(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }),
                )),
                None,
            )
        }
        other => json_response(
            StatusCode::OK,
            Some(rpc_err(id, -32601, &format!("method not found: '{other}'"))),
            None,
        ),
    }
}

/// Flatten a dispatch error into the text the model reads in an `isError`
/// result. Gate refusals keep their self-explanatory message (naming the
/// authorization flag); everything else maps to the display form.
fn dispatch_error_text(err: DispatchError) -> String {
    match err {
        DispatchError::Failure(e) => format!("{e:#}"),
        other => other.to_string(),
    }
}

/// MCP JSON-RPC routes to merge into the serve router: POST `/` and `/mcp`.
/// (`/health` stays owned by the serve module.)
pub fn routes(scan_authorized: bool) -> Router {
    Router::new()
        .route("/", post(rpc_entry))
        .route("/mcp", post(rpc_entry))
        .with_state(Arc::new(McpState { scan_authorized }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_actions_and_gating() {
        let tools = tools();
        assert_eq!(tools.len(), 11);
        for tool in tools {
            assert_eq!(tool.input_schema["type"], "object");
            assert!(!tool.description.is_empty());
        }
        let gated: Vec<&str> = tools
            .iter()
            .filter(|t| t.scan_gated)
            .map(|t| t.name)
            .collect();
        assert_eq!(gated, vec!["netscan", "portscan", "device"]);
        // Every tool name is a real action so the dispatch funnel accepts it.
        for tool in tools {
            assert!(
                crate::actions::ACTIONS.contains(&tool.name),
                "{} must be an action",
                tool.name
            );
        }
    }

    #[test]
    fn schema_marks_required_fields() {
        let s = schema(&[("a", "string", "A", true), ("b", "integer", "B", false)]);
        assert_eq!(s["required"], json!(["a"]));
        assert_eq!(s["properties"]["b"]["type"], "integer");
    }
}
