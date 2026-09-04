//! `neton serve` — the BIT Remote protocol over HTTP.
//!
//! Endpoints:
//! - `GET  /health`          → `{"ok":true}` (never token-protected)
//! - `GET  /invoke-actions`  → list of actions callable via `/invoke`
//! - `POST /invoke`          → BIT Remote protocol (params.action routing)

use std::sync::Arc;

use anyhow::Result;
use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::actions;
use crate::dispatch::{self, DispatchError};

/// Default TCP port of `neton serve` (BIT satellite convention).
pub const DEFAULT_PORT: u16 = 8753;

#[derive(Clone)]
struct AppState {
    token: Option<Arc<String>>,
    /// When false, scan actions (`netscan` / `portscan` / `device`) answer
    /// HTTP 403 — the server must be started with the explicit acknowledgement.
    scan_authorized: bool,
}

/// Build the HTTP router (exposed for tests and embedding).
pub fn router(token: Option<String>, scan_authorized: bool) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/invoke-actions", get(invoke_actions))
        .route("/invoke", post(invoke))
        .with_state(AppState {
            token: token.map(Arc::new),
            scan_authorized,
        })
}

/// Bind `host:port` and serve until the process is stopped.
pub async fn run(host: &str, port: u16, token: Option<String>, scan_authorized: bool) -> Result<()> {
    let listener = tokio::net::TcpListener::bind((host, port)).await?;
    let addr = listener.local_addr()?;
    eprintln!("neton serve listening on http://{addr} (GET /health, POST /invoke)");
    eprintln!(
        "scan actions (netscan/portscan/device): {}",
        if scan_authorized {
            "enabled"
        } else {
            "disabled (start with --yes-i-have-permission to allow)"
        }
    );
    axum::serve(listener, router(token, scan_authorized)).await?;
    Ok(())
}

/// Blocking wrapper for the synchronous CLI entry point.
pub fn run_blocking(
    host: &str,
    port: u16,
    token: Option<String>,
    scan_authorized: bool,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(host, port, token, scan_authorized))
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn invoke_actions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = check_auth(&state, &headers) {
        return response;
    }
    Json(json!({ "actions": actions::ACTIONS })).into_response()
}

#[derive(Deserialize)]
struct InvokeBody {
    #[serde(default)]
    params: Option<Value>,
}

async fn invoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<InvokeBody>, JsonRejection>,
) -> Response {
    if let Some(response) = check_auth(&state, &headers) {
        return response;
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) => return bad_request(format!("invalid request body: {rejection}")),
    };
    let Some(params) = body.params else {
        return bad_request("missing 'params' object");
    };
    match dispatch::dispatch_with(&params, state.scan_authorized) {
        Ok(value) => Json(value).into_response(),
        Err(DispatchError::UnknownAction(action)) => bad_request(format!(
            "unknown action '{action}' (available: {})",
            actions::ACTIONS.join(", ")
        )),
        Err(DispatchError::BadParams(message)) => bad_request(message),
        Err(err @ DispatchError::PermissionRequired(_)) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "ok": false, "error": err.to_string() })),
        )
            .into_response(),
        Err(DispatchError::Failure(err)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": format!("{err:#}") })),
        )
            .into_response(),
    }
}

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": message.into() })),
    )
        .into_response()
}

/// Bearer-token gate for every endpoint except `/health`.
fn check_auth(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let expected = state.token.as_deref()?;
    let ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {expected}"));
    (!ok).then(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "missing or invalid bearer token" })),
        )
            .into_response()
    })
}
