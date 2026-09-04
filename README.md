# Neton

Structured local network observation and diagnostics for AI agents — JSON in, JSON out.

[![Release](https://img.shields.io/github/v/release/yxpil/Neton?style=flat-square)](https://github.com/yxpil/Neton/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/yxpil/Neton/total?style=flat-square)](https://github.com/yxpil/Neton/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-black?style=flat-square)](./LICENSE)
[![CI](https://github.com/yxpil/Neton/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/yxpil/Neton/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-black?style=flat-square)](https://github.com/yxpil/Neton)

## About

Neton gives AI agents (especially [BIT](https://github.com/yxpil/bit)) a cross-platform, structured
view of the local network: host overview, interfaces, listening ports, DNS, TCP probes, HTTP
summaries, plus **authorized LAN discovery** (ARP table, subnet device discovery, port scanning and
per-device fingerprinting) — everything as JSON, so an agent can *read* the network instead of
scraping text.

Observation commands never send attack traffic, require no root and no promiscuous mode. The scan
commands (`netscan` / `portscan` / `device`) are plain TCP-connect based and are gated behind an
explicit authorization acknowledgement — they refuse to run until you state you own or are
authorized to test the target network. Every command prints a single JSON object on stdout; logs
and errors go to stderr.

## Features

- **`info`** — hostname, OS, architecture, default outbound IP (UDP-connect probe to 8.8.8.8, zero packets sent)
- **`interfaces`** — name, IPv4/IPv6, MAC, best-effort up/down status
- **`ports`** — listening TCP sockets + bound UDP sockets with owning pid and process name
- **`dns`** — system resolver lookup returning IPv4/IPv6 arrays and elapsed ms
- **`ping`** — TCP connect probe (no ICMP, no root), success/latency/error
- **`probe`** — concurrent TCP probing of many `host:port` targets (thread pool, default concurrency 32)
- **`http`** — request summary: status, timing, headers (sensitive ones redacted to their length), body preview
- **`arp`** — system ARP/neighbor table (macOS/Linux/Windows) with MAC-vendor lookup from an embedded OUI table; read-only, no root
- **`netscan`** *scan* — discover live devices in a subnet: concurrent TCP sweep over discovery ports, correlated with the ARP table (devices only visible via ARP are reported with `via: ["arp"]`)
- **`portscan`** *scan* — TCP connect port scan of one target; port presets `common` (40 top ports), lists (`80,443`) or ranges (`1-1024`)
- **`device`** *scan* — analyze one LAN device: MAC + vendor, reverse-DNS hostname, open ports, HTTP(S) fingerprint (`Server` header, page `<title>`) and an informational device-type guess
- **`serve`** — HTTP API on `127.0.0.1:8753` implementing the BIT Remote protocol

All commands accept `--json` (output is JSON by default) and `--pretty` (indented output).
When stdin is piped (BIT exec mode), a JSON object is read from stdin and merged over the
arguments — stdin wins.

### Scan authorization (important)

`netscan`, `portscan` and `device` touch other hosts on the network, so they refuse to run until
you acknowledge you are authorized:

```bash
neton portscan 192.168.1.1 --yes-i-have-permission
# or: NETON_I_HAVE_PERMISSION=yes neton portscan 192.168.1.1
```

- CLI without the acknowledgement exits with code **2** and explains the flag on stderr.
- `neton serve` only exposes the scan actions when started with `--yes-i-have-permission`;
  otherwise `/invoke` answers **HTTP 403** for them. `/invoke-actions` always lists all actions.
- `arp` is plain read-only observation of the local neighbor table and needs no acknowledgement.
- Only scan networks you own or are explicitly authorized to test.

## Install

Download a prebuilt binary from [Releases](https://github.com/yxpil/Neton/releases/latest):

| Platform | File |
| --- | --- |
| Linux x86_64 | `neton-v0.2.0-x86_64-unknown-linux-gnu.tar.gz` |
| macOS Apple Silicon | `neton-v0.2.0-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `neton-v0.2.0-x86_64-pc-windows-msvc.zip` |

```bash
tar xzf neton-v0.2.0-aarch64-apple-darwin.tar.gz
sudo mv neton /usr/local/bin/   # or anywhere on PATH
neton --version
```

Build from source:

```bash
cargo install --git https://github.com/yxpil/Neton
```

## Quick start

```console
$ neton info
{"hostname":"PilBrage.local","os":"macOS 26.6.2","arch":"aarch64","outbound_ip":"10.126.111.143"}

$ neton interfaces --pretty
[
  {
    "name": "lo0",
    "ipv4": ["127.0.0.1"],
    "ipv6": ["::1"],
    "mac": null,
    "status": "up",
    "loopback": true
  },
  ...
]

$ neton ports
[{"proto":"tcp","local_addr":"127.0.0.1:8753","local_ip":"127.0.0.1","local_port":8753,"pid":48211,"process":"neton","state":"Listen"}, ...]

$ neton dns localhost
{"host":"localhost","ok":true,"ipv4":["127.0.0.1"],"ipv6":["::1"],"elapsed_ms":1,"error":null}

$ neton ping example.com -p 443
{"host":"example.com","port":443,"ok":true,"elapsed_ms":23,"ip":"93.184.216.34","error":null}

$ neton probe example.com:443,127.0.0.1:22
{"total":2,"open":1,"concurrency":2,"items":[{"target":"example.com:443","ok":true,"elapsed_ms":25,"error":null},{"target":"127.0.0.1:22","ok":false,"elapsed_ms":1,"error":"127.0.0.1: Connection refused (os error 61)"}]}

$ neton http https://example.com --body-max 200
{"ok":true,"url":"https://example.com","final_url":"https://example.com/","status":200,"elapsed_ms":180,"headers":{"content-type":"text/html; charset=UTF-8","set-cookie":[{"redacted":true,"length":52}]},"body":"<!doctype html>...","error":null}

$ neton arp
[{"ip":"192.168.1.1","mac":"a4:2b:8c:11:22:33","vendor":"TP-Link","interface":"en0","state":null}, ...]

$ neton portscan 192.168.1.1 --ports common --yes-i-have-permission
{"target":"192.168.1.1","ip":"192.168.1.1","ports_scanned":40,"open_count":3,"open":[{"port":53,"service":"dns","elapsed_ms":2},{"port":80,"service":"http","elapsed_ms":2},{"port":443,"service":"https","elapsed_ms":1}],"elapsed_ms":210}

$ neton device 192.168.1.1 --yes-i-have-permission
{"ip":"192.168.1.1","hostname":"router.local","mac":"a4:2b:8c:11:22:33","vendor":"TP-Link","interface":"en0","arp_state":null,"open_ports":[...],"http":[{"url":"http://192.168.1.1:80/","status":200,"server":"Boa/0.94","powered_by":null,"title":"TP-Link Router"}],"guess":"vendor=TP-Link; router/gateway","elapsed_ms":540}

$ neton netscan 192.168.1.0/24 --yes-i-have-permission
{"cidr":"192.168.1.0/24","hosts_total":256,"ports_probed":[22,80,443,445,3389,8080],"concurrency":128,"timeout_ms":400,"devices_found":7,"devices":[{"ip":"192.168.1.1","mac":"a4:2b:8c:11:22:33","vendor":"TP-Link","hostname":null,"open_ports":[{"port":80,"service":"http","elapsed_ms":2}],"via":["tcp","arp"]}, ...],"arp_entries_seen":9,"elapsed_ms":1800}
```

Piped stdin (BIT exec-mode contract — stdin wins over CLI args):

```console
$ echo '{"host": "localhost", "port": 8753}' | neton ping
{"host":"localhost","port":8753,"ok":true,"elapsed_ms":0,"ip":"127.0.0.1","error":null}

$ echo '{"action": "ports"}' | neton        # route by action without a subcommand
[...]
```

## BIT Integration

Neton integrates with BIT in three ways.

### 1. CLI tool (exec runtime)

On BIT's **Tools** page add an interpreter runtime with id `neton` pointing to the binary
(e.g. `/usr/local/bin/neton`). Then register an exec tool — either ask the BIT agent:
"用 add_tool 注册工具：name=neton_ports，runtime=neton，code=ports"，or paste this entry into
BIT's `tools.json`:

```json
{
  "id": "neton-ports",
  "name": "neton_ports",
  "description": "List local listening TCP/UDP sockets with owning pid and process name (JSON).",
  "parameters": {
    "type": "object",
    "properties": {
      "pid": { "type": "integer", "description": "Optional: only list sockets owned by this process id" }
    }
  },
  "kind": { "kind": "interpreter", "runtime": "neton", "code": "ports" },
  "created_by": "user",
  "created_at": "2026-09-04 12:00:00",
  "enabled": true
}
```

BIT spawns `neton ports`, sends the tool parameters as JSON on stdin (merged over the args),
and reads the JSON result from stdout. Swap `code` for `info` / `interfaces` / `dns` / `ping` /
`probe` / `http` / `arp` to expose other observation actions the same way. To expose the scan
actions, also pass the authorization acknowledgement — either enable
`NETON_I_HAVE_PERMISSION=yes` in the runtime environment or append
`--yes-i-have-permission` (e.g. `code`: `portscan` and arguments `["--yes-i-have-permission"]`).

### 2. Remote tool (serve mode)

Start the server once (e.g. as a login item / service):

```bash
neton serve --port 8753                        # scan actions answer 403
neton serve --port 8753 --yes-i-have-permission # scan actions enabled
# add --token <secret> to require a Bearer token
```

Register the remote tool in BIT's `tools.json`:

```json
{
  "id": "neton-remote",
  "name": "neton_remote",
  "description": "Local network observation and authorized LAN scanning via neton serve: params.action ∈ info|interfaces|ports|dns|ping|probe|http|arp|netscan|portscan|device plus that action's arguments.",
  "parameters": {
    "type": "object",
    "properties": {
      "action": { "type": "string", "enum": ["info", "interfaces", "ports", "dns", "ping", "probe", "http", "arp", "netscan", "portscan", "device"] },
      "host": { "type": "string" },
      "port": { "type": "integer" },
      "url": { "type": "string" },
      "targets": { "type": "array", "items": { "type": "string" } },
      "cidr": { "type": "string" },
      "timeout_ms": { "type": "integer" }
    }
  },
  "kind": { "kind": "remote", "url": "http://127.0.0.1:8753/invoke" },
  "created_by": "user",
  "created_at": "2026-09-04 12:00:00",
  "enabled": true
}
```

BIT POSTs `{"tool_id": ..., "tool": ..., "invoked_by": ..., "params": {...}}` and reads the JSON
result (HTTP >= 400 is reported to the agent as an error).

### 3. Direct HTTP (curl)

```bash
curl -s http://127.0.0.1:8753/health
# {"ok":true}

curl -s http://127.0.0.1:8753/invoke-actions
# {"actions":["info","interfaces","ports","dns","ping","probe","http","arp","netscan","portscan","device"]}

curl -s -X POST http://127.0.0.1:8753/invoke -H 'Content-Type: application/json' \
  -d '{"tool_id":"neton-remote","tool":"neton_remote","invoked_by":"user","params":{"action":"ports"}}'

curl -s -X POST http://127.0.0.1:8753/invoke -H 'Content-Type: application/json' \
  -d '{"params":{"action":"ping","host":"example.com","port":443}}'

# Scan actions need the server itself to be started with --yes-i-have-permission,
# otherwise they answer 403 with an explanation.

# With --token: add  -H 'Authorization: Bearer <token>'  to every call except /health.
```

### Typical agent exchange

> **User:** 8080 端口被谁占了？
>
> **Agent:** *(调用 `neton_ports` → neton ports)*
> `[{"proto":"tcp","local_addr":"0.0.0.0:8080","local_port":8080,"pid":48211,"process":"node","state":"Listen"}]`
> 是 `node` 进程（pid 48211）在监听 0.0.0.0:8080。需要我进一步探测它响应什么吗？
>
> **User:** 看看它能不能通。
>
> **Agent:** *(调用 `neton ping`，stdin `{"host":"127.0.0.1","port":8080}`)*
> `{"ok":true,"elapsed_ms":0}` — 本机 8080 端口 TCP 可连通。

## API

### CLI

| Command | Arguments | Result JSON (top-level fields) |
| --- | --- | --- |
| `neton info` | — | `hostname?`, `os?`, `arch`, `outbound_ip?` |
| `neton interfaces` | — | `[{name, ipv4[], ipv6[], mac?, status, loopback}]` |
| `neton ports` | `--pid N?` | `[{proto, local_addr, local_ip?, local_port, pid?, process?, state?}]` |
| `neton dns` | `HOST` | `{host, ok, ipv4[], ipv6[], elapsed_ms, error?}` |
| `neton ping` | `HOST [-p PORT] [--timeout-ms MS]` | `{host, port, ok, elapsed_ms, ip?, error?}` |
| `neton probe` | `TARGETS [--concurrency N] [--timeout-ms MS]` | `{total, open, concurrency, items[]}` |
| `neton http` | `URL [--method M] [--timeout-ms MS] [--body-max N]` | `{ok, url, final_url?, status?, elapsed_ms, headers{}, body?, error?}` |
| `neton arp` | — | `[{ip, mac?, vendor?, interface?, state?}]` |
| `neton netscan` *scan* | `CIDR [--ports SPEC] [--concurrency N] [--timeout-ms MS] [--no-rdns]` | `{cidr, hosts_total, ports_probed[], concurrency, timeout_ms, devices_found, devices[], arp_entries_seen, elapsed_ms}` |
| `neton portscan` *scan* | `TARGET [--ports SPEC] [--concurrency N] [--timeout-ms MS]` | `{target, ip, ports_scanned, open_count, open[], elapsed_ms}` |
| `neton device` *scan* | `IP [--ports SPEC] [--timeout-ms MS] [--http-max N] [--no-rdns]` | `{ip, hostname?, mac?, vendor?, interface?, arp_state?, open_ports[], http[], guess, elapsed_ms}` |
| `neton serve` | `[--host H] [--port P] [--token T] [--yes-i-have-permission]` | — (HTTP server) |

`TARGETS` is a comma-separated `HOST:PORT` list (IPv6: `[::1]:8753`). `SPEC` is `common`
(40 top ports), a list (`80,443`) or a range (`1-1024`). Global flags: `--json`, `--pretty`,
`--yes-i-have-permission`. Scan commands exit with code 2 when the acknowledgement is missing.

### HTTP (serve mode, default `127.0.0.1:8753`)

| Endpoint | Method | Description |
| --- | --- | --- |
| `/health` | GET | `{"ok":true}` — never token-protected |
| `/invoke-actions` | GET | `{"actions":["info","interfaces","ports","dns","ping","probe","http","arp","netscan","portscan","device"]}` |
| `/invoke` | POST | BIT Remote protocol; `params.action` selects the action, remaining params are its arguments. Unknown action → 400, bad params → 400, unauthorized scan → 403, action failure → 500 |

Action arguments over `/invoke` (same shapes as the CLI results):

| action | params |
| --- | --- |
| `info` | — |
| `interfaces` | — |
| `ports` | `pid?` |
| `dns` | `host` |
| `ping` | `host`, `port?` (default 443), `timeout_ms?` (default 2000) |
| `probe` | `targets` (array of `host:port` or one comma-separated string), `concurrency?` (default 32), `timeout_ms?` (default 2000) |
| `http` | `url`, `method?` (default GET), `timeout_ms?` (default 5000), `body_max?` (default 500) |
| `arp` | — |
| `netscan` *scan* | `cidr` (e.g. `192.168.1.0/24`), `ports?` (SPEC, default `22,80,443,445,3389,8080`), `concurrency?` (default 128), `timeout_ms?` (default 400), `no_rdns?` (bool) |
| `portscan` *scan* | `target`, `ports?` (SPEC, default `common`), `concurrency?` (default 200), `timeout_ms?` (default 800) |
| `device` *scan* | `ip`, `ports?` (SPEC, default `common`), `timeout_ms?` (default 1000), `http_max?` (default 2, max 4), `no_rdns?` (bool) |

Observation-level failures (unreachable host, NXDOMAIN, refused connection) are returned as
`ok: false` data with HTTP 200 — the *result* is the data; only infrastructure failures are 5xx.
Scan actions additionally require the server-side authorization acknowledgement (403 otherwise).

### Notes

- `ports` lists TCP sockets in `Listen` state and bound UDP sockets; UDP has no state (`state: null`),
  port-0 pseudo-sockets are skipped. `pid`/`process` are `null` when the platform cannot provide them.
- `http` redacts `set-cookie`, `cookie`, `authorization` and `proxy-authorization` values to
  `{"redacted":true,"length":N}`.
- Scans are TCP-connect only: no raw sockets, no SYN floods, no root. `netscan` caps a scan at
  4096 hosts and 4096 ports; oversized CIDRs are rejected before any packet is sent.
- `device`'s `guess` is informational (derived from vendor/ports/page titles) — never a certainty.
- `trace` (TCP-layer hop-by-hop probing) is not implemented.

## 中文

### 简介

Neton 给 AI 智能体（尤其是 [BIT](https://github.com/yxpil/bit)）一套跨平台、结构化的本机网络
观测与诊断能力：主机概览、网卡、监听端口、DNS、TCP 探活、HTTP 摘要，以及**经授权的局域网
发现**（ARP 表、子网设备发现、端口扫描、单设备指纹分析）——全部输出 JSON，
让智能体"看懂"网络状态，而不是去解析人读的文本。

观测类命令只做观测与诊断：不发送攻击流量、无需 root、不进混杂模式。扫描类命令
（`netscan` / `portscan` / `device`）基于普通 TCP connect 实现，并且必须先显式确认
"我有权扫描目标网络"才会执行。所有命令在 stdout 输出单个 JSON 对象，日志与错误走 stderr。

### 功能

- **`info`** — 主机名、操作系统、架构、默认出口 IP（UDP connect 探测 8.8.8.8，不发任何流量）
- **`interfaces`** — 网卡名称、IPv4/IPv6、MAC、状态（尽力而为）
- **`ports`** — TCP 监听套接字 + UDP 绑定套接字，含归属 pid 与进程名
- **`dns`** — 系统解析器查询，返回 IPv4/IPv6 数组与耗时毫秒
- **`ping`** — TCP 连接探测（非 ICMP，无需 root），返回成功/耗时/错误
- **`probe`** — 并发批量 TCP 探活（线程池，默认并发 32）
- **`http`** — 请求概要：状态码、耗时、响应头（敏感头脱敏为长度）、body 预览
- **`arp`** — 系统 ARP/邻居表（macOS/Linux/Windows）+ 内置 OUI 厂商库查询；只读、无需 root
- **`netscan`** *扫描* — 子网存活设备发现：对发现端口并发 TCP 扫掠，并与 ARP 表关联
  （只在 ARP 表中出现的设备以 `via: ["arp"]` 报告）
- **`portscan`** *扫描* — 单目标 TCP connect 端口扫描；端口规格支持 `common`（40 个常用端口）、
  列表（`80,443`）与区间（`1-1024`）
- **`device`** *扫描* — 单设备分析：MAC + 厂商、反向 DNS 主机名、开放端口、HTTP(S) 指纹
  （`Server` 头、页面 `<title>`）以及信息性的设备类型推测
- **`serve`** — 在 `127.0.0.1:8753` 提供 BIT Remote 协议 HTTP API

所有命令支持 `--json`（默认即 JSON 输出）与 `--pretty`（缩进美化）。stdin 被管道输入时
（BIT exec 模式），会读取 stdin 的 JSON 对象并合并覆盖命令行参数——stdin 优先。

### 扫描授权（重要）

`netscan`、`portscan`、`device` 会触碰网络上其它主机，因此在你确认拥有授权之前拒绝执行：

```bash
neton portscan 192.168.1.1 --yes-i-have-permission
# 或者：NETON_I_HAVE_PERMISSION=yes neton portscan 192.168.1.1
```

- CLI 未带确认标志时以退出码 **2** 结束，stderr 说明所需标志。
- `neton serve` 只有以 `--yes-i-have-permission` 启动时才暴露扫描动作，否则 `/invoke`
  对它们返回 **HTTP 403**；`/invoke-actions` 始终列出全部动作。
- `arp` 是对本地邻居表的只读观测，无需确认。
- 只扫描你拥有或被明确授权测试的网络。

### 安装

从 [Releases](https://github.com/yxpil/Neton/releases/latest) 下载对应平台的二进制：

| 平台 | 文件 |
| --- | --- |
| Linux x86_64 | `neton-v0.2.0-x86_64-unknown-linux-gnu.tar.gz` |
| macOS Apple Silicon | `neton-v0.2.0-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `neton-v0.2.0-x86_64-pc-windows-msvc.zip` |

```bash
tar xzf neton-v0.2.0-aarch64-apple-darwin.tar.gz
sudo mv neton /usr/local/bin/   # 或 PATH 上任意位置
neton --version
```

源码构建：

```bash
cargo install --git https://github.com/yxpil/Neton
```

### 快速上手

```console
$ neton info
{"hostname":"PilBrage.local","os":"macOS 26.6.2","arch":"aarch64","outbound_ip":"10.126.111.143"}

$ neton ports                       # 谁在监听本机端口
$ neton dns localhost               # 域名解析 + 耗时
$ neton ping example.com -p 443     # TCP 探活（无需 root）
$ neton probe example.com:443,127.0.0.1:22   # 并发批量探活
$ neton http https://example.com    # HTTP 请求概要（敏感头自动脱敏）

$ neton arp                         # 系统 ARP 表 + OUI 厂商（只读）
$ neton portscan 192.168.1.1 --ports common --yes-i-have-permission      # 端口扫描
$ neton device 192.168.1.1 --yes-i-have-permission                       # 设备指纹分析
$ neton netscan 192.168.1.0/24 --yes-i-have-permission                   # 子网设备发现

$ echo '{"host":"localhost","port":8753}' | neton ping    # stdin 参数合并（stdin 优先）
$ echo '{"action":"ports"}' | neton                       # 无子命令时按 action 路由
```

### BIT 集成

Neton 以三种方式接入 BIT。

**方式一：CLI 工具（exec 运行时）。** 在 BIT 工具页添加解释器运行时：id 填 `neton`，
路径指向 neton 二进制（如 `/usr/local/bin/neton`）。然后注册 exec 工具——可以直接对 BIT
智能体说"用 add_tool 注册工具：name=neton_ports，runtime=neton，code=ports"，或把下面的
条目粘进 BIT 的 `tools.json`：

```json
{
  "id": "neton-ports",
  "name": "neton_ports",
  "description": "List local listening TCP/UDP sockets with owning pid and process name (JSON).",
  "parameters": {
    "type": "object",
    "properties": {
      "pid": { "type": "integer", "description": "可选：只列出该进程 id 拥有的套接字" }
    }
  },
  "kind": { "kind": "interpreter", "runtime": "neton", "code": "ports" },
  "created_by": "user",
  "created_at": "2026-09-04 12:00:00",
  "enabled": true
}
```

BIT 会启动 `neton ports`，把工具参数以 JSON 写入 stdin（合并覆盖命令行参数），从 stdout
读取 JSON 结果。把 `code` 换成 `info` / `interfaces` / `dns` / `ping` / `probe` / `http` / `arp`
即可按同样方式暴露其它观测动作。要暴露扫描动作，还需传入授权确认——在运行时环境里设置
`NETON_I_HAVE_PERMISSION=yes`，或在参数中追加 `--yes-i-have-permission`。

**方式二：Remote 工具（serve 模式）。** 先启动服务（可作为登录项/服务常驻）：

```bash
neton serve --port 8753                         # 扫描动作返回 403
neton serve --port 8753 --yes-i-have-permission # 启用扫描动作
# 加 --token <secret> 启用 Bearer 鉴权
```

在 BIT 的 `tools.json` 中注册 Remote 工具：

```json
{
  "id": "neton-remote",
  "name": "neton_remote",
  "description": "Local network observation and authorized LAN scanning via neton serve: params.action ∈ info|interfaces|ports|dns|ping|probe|http|arp|netscan|portscan|device plus that action's arguments.",
  "parameters": {
    "type": "object",
    "properties": {
      "action": { "type": "string", "enum": ["info", "interfaces", "ports", "dns", "ping", "probe", "http", "arp", "netscan", "portscan", "device"] },
      "host": { "type": "string" },
      "port": { "type": "integer" },
      "url": { "type": "string" },
      "targets": { "type": "array", "items": { "type": "string" } },
      "cidr": { "type": "string" },
      "timeout_ms": { "type": "integer" }
    }
  },
  "kind": { "kind": "remote", "url": "http://127.0.0.1:8753/invoke" },
  "created_by": "user",
  "created_at": "2026-09-04 12:00:00",
  "enabled": true
}
```

BIT 会 POST `{"tool_id": ..., "tool": ..., "invoked_by": ..., "params": {...}}` 并读取 JSON
结果（HTTP >= 400 会作为错误反馈给智能体）。

**方式三：直接 HTTP（curl）。**

```bash
curl -s http://127.0.0.1:8753/health
# {"ok":true}

curl -s http://127.0.0.1:8753/invoke-actions
# {"actions":["info","interfaces","ports","dns","ping","probe","http","arp","netscan","portscan","device"]}

curl -s -X POST http://127.0.0.1:8753/invoke -H 'Content-Type: application/json' \
  -d '{"tool_id":"neton-remote","tool":"neton_remote","invoked_by":"user","params":{"action":"ports"}}'

curl -s -X POST http://127.0.0.1:8753/invoke -H 'Content-Type: application/json' \
  -d '{"params":{"action":"ping","host":"example.com","port":443}}'

# 扫描动作要求服务本身以 --yes-i-have-permission 启动，否则返回 403 并说明原因。

# 启用了 --token 时，除 /health 外每个请求加：-H 'Authorization: Bearer <token>'
```

**智能体典型问答示例：**

> **用户：** 8080 端口被谁占了？
>
> **智能体：** *（调用 neton_ports → neton ports）*
> `[{"proto":"tcp","local_addr":"0.0.0.0:8080","local_port":8080,"pid":48211,"process":"node","state":"Listen"}]`
> 是 `node` 进程（pid 48211）在监听 0.0.0.0:8080。需要我进一步探测它响应什么吗？
>
> **用户：** 看看它能不能通。
>
> **智能体：** *（调用 neton ping，stdin 传 `{"host":"127.0.0.1","port":8080}`）*
> `{"ok":true,"elapsed_ms":0}` — 本机 8080 端口 TCP 可连通。

### API

CLI 与 HTTP API 的完整字段说明见上文 [API](#api) 章节（中英同构：所有动作的返回结构一致）。

| 子命令 | 参数 | 返回 JSON 顶层字段 |
| --- | --- | --- |
| `neton info` | — | `hostname?`, `os?`, `arch`, `outbound_ip?` |
| `neton interfaces` | — | `[{name, ipv4[], ipv6[], mac?, status, loopback}]` |
| `neton ports` | `--pid N?` | `[{proto, local_addr, local_ip?, local_port, pid?, process?, state?}]` |
| `neton dns` | `HOST` | `{host, ok, ipv4[], ipv6[], elapsed_ms, error?}` |
| `neton ping` | `HOST [-p PORT] [--timeout-ms MS]` | `{host, port, ok, elapsed_ms, ip?, error?}` |
| `neton probe` | `TARGETS [--concurrency N] [--timeout-ms MS]` | `{total, open, concurrency, items[]}` |
| `neton http` | `URL [--method M] [--timeout-ms MS] [--body-max N]` | `{ok, url, final_url?, status?, elapsed_ms, headers{}, body?, error?}` |
| `neton arp` | — | `[{ip, mac?, vendor?, interface?, state?}]` |
| `neton netscan` *扫描* | `CIDR [--ports SPEC] [--concurrency N] [--timeout-ms MS] [--no-rdns]` | `{cidr, hosts_total, ports_probed[], concurrency, timeout_ms, devices_found, devices[], arp_entries_seen, elapsed_ms}` |
| `neton portscan` *扫描* | `TARGET [--ports SPEC] [--concurrency N] [--timeout-ms MS]` | `{target, ip, ports_scanned, open_count, open[], elapsed_ms}` |
| `neton device` *扫描* | `IP [--ports SPEC] [--timeout-ms MS] [--http-max N] [--no-rdns]` | `{ip, hostname?, mac?, vendor?, interface?, arp_state?, open_ports[], http[], guess, elapsed_ms}` |
| `neton serve` | `[--host H] [--port P] [--token T] [--yes-i-have-permission]` | — （HTTP 服务） |

`SPEC` 端口规格：`common`（40 个常用端口）、列表（`80,443`）或区间（`1-1024`）。
全局标志：`--json`、`--pretty`、`--yes-i-have-permission`。扫描命令缺少确认标志时以退出码 2 结束。

HTTP 端点：`GET /health`（`{"ok":true}`，不受 token 保护）、`GET /invoke-actions`（动作列表，
共 11 个）、`POST /invoke`（BIT Remote 协议：`params.action` 选择动作，其余字段为该动作参数；
未知 action → 400，参数错误 → 400，未授权扫描 → 403，动作执行失败 → 500）。

### 家庭网络排查示例

```console
$ neton arp                                  # 1) 看看局域网里有哪些设备、什么厂商
[{"ip":"192.168.1.1","mac":"a4:2b:8c:11:22:33","vendor":"TP-Link",...},
 {"ip":"192.168.1.105","mac":"5c:cf:7f:aa:bb:cc","vendor":"Espressif",...}]

$ neton netscan 192.168.1.0/24 --yes-i-have-permission    # 2) 全子网设备发现（TCP + ARP）
{"devices_found":7, "devices":[{"ip":"192.168.1.1",...,"via":["tcp","arp"]}, ...]}

$ neton device 192.168.1.105 --yes-i-have-permission      # 3) 深挖某台设备
{"ip":"192.168.1.105","vendor":"Espressif","open_ports":[{"port":80,"service":"http"}],
 "http":[{"status":200,"title":"ESP Web Server"}],"guess":"vendor=Espressif"}
```

### 安全与合规

- 观测类命令只做观测与诊断：DNS 查询、TCP 连接、HTTP GET/HEAD 类请求。
- 扫描类命令（`netscan` / `portscan` / `device`）只做 TCP connect 探测：无原始套接字、
  无 SYN 洪水、无需 root，并且必须先显式确认授权（CLI 退出码 2 / HTTP 403 双重门控）；
  子网规模上限 4096 主机、4096 端口，超限的 CIDR 在发包前即被拒绝。
  漏洞利用与渗透不在范围内（那是 [Firelin](https://github.com/yxpil/Firelin) 的职责）。
- 无需 root/管理员权限；`ping` 是 TCP connect 而非 ICMP。
- `info` 的出口 IP 通过 UDP connect 探测路由表获得，不发送任何数据包。
- 敏感响应头（`set-cookie` / `cookie` / `authorization` / `proxy-authorization`）只输出长度，
  不回显内容；HTTP body 只保留前 N 字符。
- `device` 的 `guess` 仅为信息性推测（基于厂商/端口/页面标题），不构成判定。
- `serve` 默认只绑定 `127.0.0.1`；如需 Bearer 鉴权请加 `--token`（`/health` 除外）；
  扫描动作需以 `--yes-i-have-permission` 启动服务才会放行。
- 只扫描你拥有或被明确授权测试的网络。

---

Part of the [BIT](https://github.com/yxpil/bit) ecosystem — a desktop AI agent hub and its
satellite tools. Neton observes the network; [Firelin](https://github.com/yxpil/Firelin) attacks it.

Licensed under [Apache-2.0](./LICENSE).
