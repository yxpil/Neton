# Neton 测试说明
- 测试完成：是（2026-10-04）
- 测试日期：2026-10-04
- 测试内容：单元覆盖 models/oui/scan(端口·CIDR 解析)/dispatch 参数校验/arp/dns_ptr 纯函数；集成覆盖 cli 二进制、serve(axum `/invoke`)、mcp(JSON-RPC)；注入测试覆盖参数解析器与 bearer 门（XSS 与 shell 串作为 host 被当数据返回、路径穿越/端口越界被解析拒绝、JSON 类型混淆 400、SQL 式 token 绕过 401）。无运行时钩子/插件/事件机制。
- 运行命令：`cargo test`（仓库根）
- 测试框架：Rust `#[cfg(test)]` + `cargo test`（集成测试位于 `tests/`）
- 模型：豆包（Doubao）生成

# Testing Neton

Neton is a structured local-network observation tool (JSON in, JSON out). It has
three test layers, all driven by `cargo test`:

| Layer | Location | What it covers |
|-------|----------|----------------|
| Unit tests | `src/**/*.rs` (`#[cfg(test)] mod tests`) | Pure functions: model (de)serialization, OUI lookup, CIDR/port-spec parsing, piped-stdin arg merge, dispatch validation, ARP output parsing, reverse-DNS wire format. |
| Integration / CLI | `tests/cli.rs` | The compiled binary end-to-end: `info`, `interfaces`, `ports`, `dns`, `ping`, `probe`, `http`, `arp`, permission-gated scans, piped-stdin merge. |
| Integration / HTTP | `tests/serve.rs`, `tests/mcp.rs` | The real axum router on loopback: BIT `POST /invoke`, bearer-token gate, scan authorization, MCP JSON-RPC handshake / tools / errors. |
| Parser edge cases | `tests/parsing.rs` | Unit-style tests of the public pure parsers (`scan::parse_port_spec`, `scan::parse_cidr`, `cli::MergeStdin`, `dispatch`) focused on whitespace, range bounds, numeric overflow and JSON type confusion. |
| Injection / security | `tests/injection.rs` | Untrusted-input robustness — see below. |

## Run

```sh
cargo test
```

Everything is loopback-only: the only ports opened are ephemeral loopback
listeners created inside tests, and scans are run against `127.0.0.1`. No real
network is touched.

## What the injection tests assert

Neton never spawns a shell, never touches a database and never serves files
from a request path, so its injection surface is the action-parameter parser plus
the bearer-token gate. `tests/injection.rs` proves hostile input is rejected or
treated as opaque data rather than executed:

- malformed JSON body and non-object `params` → HTTP 400 (never a 500 crash);
- XSS markup / shell metacharacters passed as a `dns` host are echoed verbatim
  inside a JSON `{ok:false}` result — never rendered as HTML, never shell-expanded;
- path-traversal strings as `cidr`/`ip`/`ports` are rejected during parsing with
  no file read;
- a `javascript:` URL to the `http` action is returned as data (`ok:false`), not fetched;
- wrong JSON types / negative or oversized numbers → clean 400, never a panic;
- SQL-style payloads (`' OR 1=1 --`, …) do not defeat the exact-match bearer token (401).

## Hook / plugin tests

Neton exposes a **static, built-in** tool registry (the 11 MCP tools are fixed at
compile time); there is no user-registerable hook, plugin, event or callback
mechanism. There are therefore **0 hook tests** — nothing in the codebase
registers or dispatches runtime callbacks.

## Expected result

`cargo test` should finish green. As of this document the suites are:
unit 55, `cli.rs` 22, `serve.rs` 10, `mcp.rs` 12, `parsing.rs` 7, `injection.rs` 10
(passing:failing = 116:0).
