//! Shared action routing used by `serve` (`POST /invoke`) and by bare
//! `neton` when a JSON object is piped on stdin without a subcommand.

use anyhow::Result;
use serde_json::{json, Value};

use crate::actions;

/// Why an action call could not be dispatched.
#[derive(Debug)]
pub enum DispatchError {
    /// `params.action` is not a known action (maps to HTTP 400).
    UnknownAction(String),
    /// The action parameters are missing or malformed (maps to HTTP 400).
    BadParams(String),
    /// The action itself failed (maps to HTTP 500).
    Failure(anyhow::Error),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::UnknownAction(action) => write!(
                f,
                "unknown action '{action}' (available: {})",
                actions::ACTIONS.join(", ")
            ),
            DispatchError::BadParams(message) => write!(f, "{message}"),
            DispatchError::Failure(err) => write!(f, "{err:#}"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// Route one action call. `params` must contain `action` (or `tool`) plus the
/// action's arguments; unknown extra keys are ignored.
pub fn dispatch(params: &Value) -> std::result::Result<Value, DispatchError> {
    let obj = match params.as_object() {
        Some(obj) => obj,
        None => {
            return Err(DispatchError::BadParams(
                "'params' must be a JSON object".into(),
            ));
        }
    };
    let action = obj
        .get("action")
        .or_else(|| obj.get("tool"))
        .and_then(Value::as_str)
        .ok_or_else(|| DispatchError::BadParams("missing 'action' (or 'tool') in params".into()))?
        .to_string();

    let get_str = |key: &str| -> std::result::Result<Option<String>, DispatchError> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(DispatchError::BadParams(format!(
                "'{key}' must be a string"
            ))),
        }
    };
    let get_num = |key: &str| -> std::result::Result<Option<u64>, DispatchError> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| {
                DispatchError::BadParams(format!("'{key}' must be a non-negative integer"))
            }),
            Some(_) => Err(DispatchError::BadParams(format!(
                "'{key}' must be a number"
            ))),
        }
    };
    let bad = |message: &str| DispatchError::BadParams(message.to_string());

    match action.as_str() {
        "info" => actions::info()
            .map(|v| json!(v))
            .map_err(DispatchError::Failure),
        "interfaces" => actions::interfaces()
            .map(|v| json!(v))
            .map_err(DispatchError::Failure),
        "ports" => {
            let pid = match get_num("pid")? {
                Some(raw) => Some(u32::try_from(raw).map_err(|_| bad("'pid' is out of range"))?),
                None => None,
            };
            actions::ports(pid)
                .map(|v| json!(v))
                .map_err(DispatchError::Failure)
        }
        "dns" => {
            let host = get_str("host")?.ok_or_else(|| bad("dns requires 'host'"))?;
            Ok(json!(actions::dns(&host)))
        }
        "ping" => {
            let host = get_str("host")?.ok_or_else(|| bad("ping requires 'host'"))?;
            let port = get_num("port")?
                .map(|raw| u16::try_from(raw).map_err(|_| bad("'port' is out of range")))
                .transpose()?
                .unwrap_or(actions::DEFAULT_PING_PORT);
            let timeout_ms = get_num("timeout_ms")?.unwrap_or(actions::DEFAULT_TIMEOUT_MS);
            Ok(json!(actions::ping(&host, port, timeout_ms)))
        }
        "probe" => {
            let targets = parse_targets(obj.get("targets"))?;
            let concurrency = get_num("concurrency")?
                .unwrap_or(actions::DEFAULT_PROBE_CONCURRENCY as u64)
                as usize;
            let timeout_ms = get_num("timeout_ms")?.unwrap_or(actions::DEFAULT_TIMEOUT_MS);
            actions::probe(&targets, concurrency, timeout_ms)
                .map(|v| json!(v))
                .map_err(DispatchError::Failure)
        }
        "http" => {
            let url = get_str("url")?.ok_or_else(|| bad("http requires 'url'"))?;
            let method = get_str("method")?.unwrap_or_else(|| "GET".into());
            let timeout_ms = get_num("timeout_ms")?.unwrap_or(actions::DEFAULT_HTTP_TIMEOUT_MS);
            let body_max =
                get_num("body_max")?.unwrap_or(actions::DEFAULT_HTTP_BODY_MAX as u64) as usize;
            actions::http(&url, &method, timeout_ms, body_max)
                .map(|v| json!(v))
                .map_err(DispatchError::Failure)
        }
        other => Err(DispatchError::UnknownAction(other.to_string())),
    }
}

fn parse_targets(value: Option<&Value>) -> std::result::Result<Vec<String>, DispatchError> {
    let malformed = || {
        DispatchError::BadParams(
            "'targets' must be an array of \"host:port\" strings or one comma-separated string"
                .into(),
        )
    };
    match value {
        None | Some(Value::Null) => {
            Err(DispatchError::BadParams("probe requires 'targets'".into()))
        }
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string).ok_or_else(malformed))
            .collect(),
        Some(Value::String(s)) => Ok(s
            .split(',')
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .map(str::to_string)
            .collect()),
        Some(_) => Err(malformed()),
    }
}

/// Convenience wrapper for CLI use: every dispatch failure becomes an error.
pub fn dispatch_or_fail(params: &Value) -> Result<Value> {
    dispatch(params).map_err(|err| anyhow::anyhow!("{err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_action_is_reported() {
        let err = dispatch(&json!({ "action": "nope" })).unwrap_err();
        assert!(matches!(err, DispatchError::UnknownAction(a) if a == "nope"));
    }

    #[test]
    fn missing_action_is_bad_params() {
        let err = dispatch(&json!({ "host": "localhost" })).unwrap_err();
        assert!(matches!(err, DispatchError::BadParams(_)));
    }

    #[test]
    fn tool_key_is_accepted_as_alias() {
        let out = dispatch(&json!({ "tool": "dns", "host": "localhost" })).unwrap();
        assert_eq!(out["ok"], json!(true));
    }

    #[test]
    fn missing_required_param_is_bad_params() {
        let err = dispatch(&json!({ "action": "dns" })).unwrap_err();
        assert!(matches!(err, DispatchError::BadParams(_)));
    }
}
