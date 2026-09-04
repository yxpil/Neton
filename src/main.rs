//! neton CLI entry point: parse arguments, merge piped stdin JSON, dispatch,
//! print JSON on stdout, errors on stderr.

use std::io::{IsTerminal, Read};
use std::net::IpAddr;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use serde::Serialize;
use serde_json::Value;

use neton::actions;
use neton::cli::{Cli, Command, MergeStdin};
use neton::dispatch;
use neton::scan;
use neton::serve;

fn main() -> ExitCode {
    match run() {
        Ok(Some(json)) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("neton: {err:#}");
            // Missing scan authorization is a usage problem, not a crash.
            if err.downcast_ref::<scan::PermissionRequired>().is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Read a JSON object from stdin when it is piped (BIT exec-mode contract).
fn read_stdin_object() -> Result<Option<Value>> {
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .context("failed to read piped stdin")?;
    let trimmed = buffer.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let value: Value = serde_json::from_str(trimmed).context("piped stdin is not valid JSON")?;
    if !value.is_object() {
        bail!("piped stdin JSON must be an object");
    }
    Ok(Some(value))
}

fn emit<T: Serialize>(value: &T, pretty: bool) -> Result<Option<String>> {
    let json = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    Ok(Some(json))
}

fn require<'a>(value: &'a Option<String>, field: &str, action: &str) -> Result<&'a str> {
    value.as_deref().with_context(|| {
        format!("{action} requires '{field}' (command line argument or piped stdin JSON)")
    })
}

fn run() -> Result<Option<String>> {
    let cli = Cli::parse();
    let stdin = read_stdin_object()?;
    let scan_allowed = cli.yes_i_have_permission || scan::permission_via_env();

    match cli.command {
        Some(Command::Info) => emit(&actions::info()?, cli.pretty),
        Some(Command::Interfaces) => emit(&actions::interfaces()?, cli.pretty),
        Some(Command::Ports(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            emit(&actions::ports(args.pid)?, cli.pretty)
        }
        Some(Command::Dns(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            let host = require(&args.host, "host", "dns")?;
            emit(&actions::dns(host), cli.pretty)
        }
        Some(Command::Ping(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            let host = require(&args.host, "host", "ping")?;
            let port = args.port.unwrap_or(actions::DEFAULT_PING_PORT);
            let timeout_ms = args.timeout_ms.unwrap_or(actions::DEFAULT_TIMEOUT_MS);
            emit(&actions::ping(host, port, timeout_ms), cli.pretty)
        }
        Some(Command::Probe(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            let targets: Vec<String> = require(&args.targets, "targets", "probe")?
                .split(',')
                .map(str::trim)
                .filter(|target| !target.is_empty())
                .map(str::to_string)
                .collect();
            if targets.is_empty() {
                bail!("probe requires at least one HOST:PORT target");
            }
            let concurrency = args
                .concurrency
                .unwrap_or(actions::DEFAULT_PROBE_CONCURRENCY);
            let timeout_ms = args.timeout_ms.unwrap_or(actions::DEFAULT_TIMEOUT_MS);
            emit(
                &actions::probe(&targets, concurrency, timeout_ms)?,
                cli.pretty,
            )
        }
        Some(Command::Http(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            let url = require(&args.url, "url", "http")?;
            let method = args.method.as_deref().unwrap_or("GET");
            let timeout_ms = args.timeout_ms.unwrap_or(actions::DEFAULT_HTTP_TIMEOUT_MS);
            let body_max = args.body_max.unwrap_or(actions::DEFAULT_HTTP_BODY_MAX);
            emit(
                &actions::http(url, method, timeout_ms, body_max)?,
                cli.pretty,
            )
        }
        Some(Command::Serve(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            let host = args.host.unwrap_or_else(|| "127.0.0.1".into());
            let port = args.port.unwrap_or(serve::DEFAULT_PORT);
            let serve_scan_authorized = args.yes_i_have_permission || scan::permission_via_env();
            serve::run_blocking(&host, port, args.token, serve_scan_authorized)?;
            Ok(None)
        }
        Some(Command::Arp) => emit(&neton::arp::read_arp_table()?, cli.pretty),
        Some(Command::NetScan(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            scan::ensure_scan_permission("netscan", scan_allowed)?;
            let cidr = require(&args.cidr, "cidr", "netscan")?.to_string();
            let ports = parse_ports_or_default(args.ports.as_deref(), scan::DEFAULT_NETSCAN_PORTS.to_vec())?;
            let concurrency = args.concurrency.unwrap_or(scan::DEFAULT_NETSCAN_CONCURRENCY as usize);
            let timeout_ms = args.timeout_ms.unwrap_or(scan::DEFAULT_NETSCAN_TIMEOUT_MS);
            emit(
                &scan::netscan(&cidr, &ports, concurrency, timeout_ms, !args.no_rdns)?,
                cli.pretty,
            )
        }
        Some(Command::PortScan(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            scan::ensure_scan_permission("portscan", scan_allowed)?;
            let target = require(&args.target, "target", "portscan")?.to_string();
            let ports = parse_ports_or_default(args.ports.as_deref(), scan::COMMON_PORTS.to_vec())?;
            let concurrency = args
                .concurrency
                .unwrap_or(scan::DEFAULT_PORTSCAN_CONCURRENCY as usize);
            let timeout_ms = args.timeout_ms.unwrap_or(scan::DEFAULT_PORTSCAN_TIMEOUT_MS);
            emit(&scan::portscan(&target, &ports, concurrency, timeout_ms)?, cli.pretty)
        }
        Some(Command::Device(mut args)) => {
            if let Some(value) = &stdin {
                args.merge_stdin(value)?;
            }
            scan::ensure_scan_permission("device", scan_allowed)?;
            let ip: IpAddr = require(&args.ip, "ip", "device")?
                .parse()
                .context("'ip' must be an IPv4 or IPv6 address")?;
            let ports = match args.ports.as_deref() {
                Some(spec) => Some(scan::parse_port_spec(spec)?),
                None => None,
            };
            let timeout_ms = args.timeout_ms.unwrap_or(neton::device::DEFAULT_DEVICE_TIMEOUT_MS);
            let http_max = args.http_max.unwrap_or(neton::device::DEFAULT_HTTP_MAX);
            emit(
                &neton::device::analyze(ip, ports.as_deref(), timeout_ms, http_max, !args.no_rdns)?,
                cli.pretty,
            )
        }
        None => match stdin {
            Some(value) => {
                match dispatch::dispatch_with(&value, scan_allowed) {
                    Ok(out) => emit(&out, cli.pretty),
                    Err(dispatch::DispatchError::PermissionRequired(action)) => Err(anyhow::Error::new(
                        scan::PermissionRequired { action },
                    )),
                    Err(err) => Err(anyhow::anyhow!("{err}")),
                }
            }
            None => {
                Cli::command()
                    .print_help()
                    .context("failed to print help")?;
                Ok(None)
            }
        },
    }
}

/// Parse a port spec, or fall back to the action's default port set.
fn parse_ports_or_default(spec: Option<&str>, default: Vec<u16>) -> Result<Vec<u16>> {
    match spec {
        Some(spec) => scan::parse_port_spec(spec),
        None => Ok(default),
    }
}
