//! neton CLI entry point: parse arguments, merge piped stdin JSON, dispatch,
//! print JSON on stdout, errors on stderr.

use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use serde::Serialize;
use serde_json::Value;

use neton::actions;
use neton::cli::{Cli, Command, MergeStdin};
use neton::dispatch;
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
            ExitCode::FAILURE
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
            serve::run_blocking(&host, port, args.token)?;
            Ok(None)
        }
        None => match stdin {
            Some(value) => emit(&dispatch::dispatch_or_fail(&value)?, cli.pretty),
            None => {
                Cli::command()
                    .print_help()
                    .context("failed to print help")?;
                Ok(None)
            }
        },
    }
}
