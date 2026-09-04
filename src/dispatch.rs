//! Shared action routing used by `serve` (`POST /invoke`) and by bare
//! `neton` when a JSON object is piped on stdin without a subcommand.

use anyhow::Result;
use serde_json::{json, Value};
use std::net::IpAddr;

use crate::actions;

/// Why an action call could not be dispatched.
#[derive(Debug)]
pub enum DispatchError {
    /// `params.action` is not a known action (maps to HTTP 400).
    UnknownAction(String),
    /// The action parameters are missing or malformed (maps to HTTP 400).
    BadParams(String),
    /// A scan action was called without the server-side authorization
    /// acknowledgement (maps to HTTP 403).
    PermissionRequired(String),
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
            DispatchError::PermissionRequired(action) => write!(
                f,
                "action '{action}' is a network scan: restart `neton serve` with \
                 --yes-i-have-permission (or NETON_I_HAVE_PERMISSION=yes) to allow it — \
                 only scan networks you own or are authorized to test"
            ),
            DispatchError::Failure(err) => write!(f, "{err:#}"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// Route one action call. `params` must contain `action` (or `tool`) plus the
/// action's arguments; unknown extra keys are ignored. `scan_authorized`
/// enables the scan actions (`netscan` / `portscan` / `device`).
pub fn dispatch_with(
    params: &Value,
    scan_authorized: bool,
) -> std::result::Result<Value, DispatchError> {
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
    let get_bool = |key: &str| -> std::result::Result<Option<bool>, DispatchError> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(DispatchError::BadParams(format!(
                "'{key}' must be a boolean"
            ))),
        }
    };
    let bad = |message: &str| DispatchError::BadParams(message.to_string());
    let scan_ports = |key: &str| -> std::result::Result<Option<Vec<u16>>, DispatchError> {
        get_str(key)?
            .map(|spec| {
                crate::scan::parse_port_spec(&spec)
                    .map_err(|e| bad(&format!("invalid '{key}': {e:#}")))
            })
            .transpose()
    };

    // Scan actions require an explicit authorization acknowledgement.
    if crate::scan::SCAN_ACTIONS.contains(&action.as_str()) && !scan_authorized {
        return Err(DispatchError::PermissionRequired(action));
    }

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
        // ------------------------------------------------- scans (gated) ----
        "arp" => crate::arp::read_arp_table()
            .map(|v| json!(v))
            .map_err(DispatchError::Failure),
        "netscan" => {
            let cidr = get_str("cidr")?.ok_or_else(|| bad("netscan requires 'cidr'"))?;
            let ports =
                scan_ports("ports")?.unwrap_or_else(|| crate::scan::DEFAULT_NETSCAN_PORTS.to_vec());
            let concurrency = get_num("concurrency")?
                .unwrap_or(crate::scan::DEFAULT_NETSCAN_CONCURRENCY)
                as usize;
            let timeout_ms =
                get_num("timeout_ms")?.unwrap_or(crate::scan::DEFAULT_NETSCAN_TIMEOUT_MS);
            let rdns = !get_bool("no_rdns")?.unwrap_or(false);
            crate::scan::netscan(&cidr, &ports, concurrency, timeout_ms, rdns)
                .map(|v| json!(v))
                .map_err(DispatchError::Failure)
        }
        "portscan" => {
            let target = get_str("target")?.ok_or_else(|| bad("portscan requires 'target'"))?;
            let ports = scan_ports("ports")?.unwrap_or_else(|| crate::scan::COMMON_PORTS.to_vec());
            let concurrency = get_num("concurrency")?
                .unwrap_or(crate::scan::DEFAULT_PORTSCAN_CONCURRENCY)
                as usize;
            let timeout_ms =
                get_num("timeout_ms")?.unwrap_or(crate::scan::DEFAULT_PORTSCAN_TIMEOUT_MS);
            crate::scan::portscan(&target, &ports, concurrency, timeout_ms)
                .map(|v| json!(v))
                .map_err(DispatchError::Failure)
        }
        "device" => {
            let ip_str = get_str("ip")?.ok_or_else(|| bad("device requires 'ip'"))?;
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| bad("'ip' must be an IPv4 or IPv6 address"))?;
            let ports = scan_ports("ports")?;
            let timeout_ms =
                get_num("timeout_ms")?.unwrap_or(crate::device::DEFAULT_DEVICE_TIMEOUT_MS);
            let http_max =
                get_num("http_max")?.unwrap_or(crate::device::DEFAULT_HTTP_MAX as u64) as usize;
            let rdns = !get_bool("no_rdns")?.unwrap_or(false);
            crate::device::analyze(ip, ports.as_deref(), timeout_ms, http_max, rdns)
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

/// Convenience wrapper for CLI stdin mode: scan actions are authorized via
/// the `NETON_I_HAVE_PERMISSION=yes` environment variable.
pub fn dispatch(params: &Value) -> std::result::Result<Value, DispatchError> {
    dispatch_with(params, crate::scan::permission_via_env())
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

    #[test]
    fn scan_actions_require_authorization() {
        for action in ["netscan", "portscan", "device"] {
            let err = dispatch_with(&json!({ "action": action }), false).unwrap_err();
            assert!(
                matches!(err, DispatchError::PermissionRequired(ref a) if a == action),
                "{action} must be gated"
            );
        }
    }

    #[test]
    fn scan_action_params_still_validated_when_gated() {
        // Bad params win over the permission error only when authorized;
        // unauthorized always answers PermissionRequired first.
        let err = dispatch_with(&json!({ "action": "netscan", "ports": "not-a-port" }), true)
            .unwrap_err();
        assert!(matches!(err, DispatchError::BadParams(_)));
    }

    #[test]
    fn portscan_action_scans_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = dispatch_with(
            &json!({ "action": "portscan", "target": "127.0.0.1", "ports": port.to_string() }),
            true,
        )
        .unwrap();
        assert_eq!(out["target"], "127.0.0.1");
        assert_eq!(out["open_count"], 1);
        assert_eq!(out["open"][0]["port"], port as u64);
    }

    #[test]
    fn device_action_requires_valid_ip() {
        let err =
            dispatch_with(&json!({ "action": "device", "ip": "not-an-ip" }), true).unwrap_err();
        assert!(matches!(err, DispatchError::BadParams(_)));
    }

    #[test]
    fn device_action_reports_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = dispatch_with(
            &json!({
                "action": "device",
                "ip": "127.0.0.1",
                "ports": port.to_string(),
                "timeout_ms": 500,
                "http_max": 0,
                "no_rdns": true
            }),
            true,
        )
        .unwrap();
        assert_eq!(out["ip"], "127.0.0.1");
        assert_eq!(out["open_ports"][0]["port"], port as u64);
        assert!(out["guess"].is_string());
    }
}
