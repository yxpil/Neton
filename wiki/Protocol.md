# Neton HTTP Protocol / Neton HTTP 协议

Neton `serve` mode exposes a small HTTP API on `127.0.0.1:8753` by default (`--host/--port` overridable). All responses are JSON.

Neton `serve` 模式默认在 `127.0.0.1:8753` 提供一个小型 HTTP API（可用 `--host/--port` 覆盖）。所有响应均为 JSON。

## Endpoints / 端点

| Endpoint / 端点 | Method / 方法 | Auth / 认证 | Description / 说明 |
| --- | --- | --- | --- |
| `/health` | GET | none / 无 | Liveness probe. Returns / 返回 `{"ok":true}` — never token-protected / 永不做 token 保护 |
| `/invoke-actions` | GET | Bearer (optional / 可选) | `{"actions":["info","interfaces","ports","dns","ping","probe","http","arp","netscan","portscan","device"]}` |
| `/invoke` | POST | Bearer (optional / 可选) | BIT Remote protocol entry / BIT Remote 协议入口 |

With `serve --token <TOKEN>`, `/invoke-actions` and `/invoke` require `Authorization: Bearer <TOKEN>` (401 otherwise); `/health` stays open. / 使用 `serve --token <TOKEN>` 后，`/invoke-actions` 与 `/invoke` 需要 `Authorization: Bearer <TOKEN>`（否则 401）；`/health` 保持开放。

## Scan authorization / 扫描授权

Scan actions (`netscan`, `portscan`, `device`) are only served when the process was started with `--yes-i-have-permission` or `NETON_I_HAVE_PERMISSION=yes`. Otherwise `/invoke` answers HTTP **403** for them. `/invoke-actions` always lists all actions. There is no per-request way to authorize — the gate is bound to the serve process at startup.

扫描动作（`netscan`、`portscan`、`device`）仅在进程以 `--yes-i-have-permission` 或 `NETON_I_HAVE_PERMISSION=yes` 启动时可用，否则 `/invoke` 对其返回 HTTP **403**。`/invoke-actions` 始终列出全部动作。授权在 serve 启动时绑定，无法按请求临时授权。

## POST /invoke

Request body (BIT Remote payload) / 请求体（BIT Remote 载荷）:

```json
{
  "tool_id": "tool-uuid",
  "tool": "neton",
  "invoked_by": "bit-agent",
  "params": { "action": "portscan", "target": "192.168.1.1", "ports": "80,443" }
}
```

Routing reads `params.action`, falling back to `params.tool`; the remaining params are the action's arguments. Valid actions / 路由读取 `params.action`（回退 `params.tool`），其余参数即动作参数。合法 action：

| action | Params / 参数 | Response payload / 响应载荷 |
| --- | --- | --- |
| `info` | — | `{hostname, os, arch, outbound_ip, ...}` |
| `interfaces` | — | `[{name, ipv4[], ipv6[], mac?, status}]` |
| `ports` | `pid?` | `[{proto, local_addr, port, state, pid?, process?}]` |
| `dns` | `host` | `{host, ipv4[], ipv6[], elapsed_ms}` |
| `ping` | `host`, `port?` (默认 443), `timeout_ms?` (默认 2000) | `{host, port, ok, elapsed_ms?, error?}` |
| `probe` | `targets`（数组或逗号分隔字符串 `host:port`）、`concurrency?` (32)、`timeout_ms?` (2000) | `{probed, alive[], dead[], elapsed_ms}` |
| `http` | `url`, `method?` (GET)、`timeout_ms?` (5000)、`body_max?` (500) | `{url, status, elapsed_ms, headers{...redacted}, body_preview?}` |
| `arp` | — | `[{ip, mac?, vendor?, interface?, state?}]` |
| `netscan` *scan* | `cidr`（如 `192.168.1.0/24`）、`ports?` (默认 `22,80,443,445,3389,8080`)、`concurrency?` (128)、`timeout_ms?` (400)、`no_rdns?` | `{cidr, hosts_total, ports_probed[], devices_found, devices[], arp_entries_seen, elapsed_ms}` |
| `portscan` *scan* | `target`、`ports?` (`common` / 列表 / 区间, 默认 `common`)、`concurrency?` (200)、`timeout_ms?` (800) | `{target, ip, ports_scanned, open_count, open[], elapsed_ms}` |
| `device` *scan* | `ip`、`ports?` (默认 `common`)、`timeout_ms?` (1000)、`http_max?` (2, 上限 4)、`no_rdns?` | `{ip, hostname?, mac?, vendor?, open_ports[], http[], guess, elapsed_ms}` |

### Error semantics / 错误语义

| HTTP | Meaning / 含义 |
| --- | --- |
| 200 | Success — including observation-level failures: unreachable host, NXDOMAIN, refused connection are returned as `ok: false` *data*; the result is the data / 成功 —— 观测级失败（主机不可达、域名不存在、连接拒绝）也以 `ok:false` 数据返回 |
| 400 | Unknown `action`, missing/invalid params / 未知动作、参数缺失或非法 |
| 401 | Missing or invalid Bearer token / 缺失或错误的 Bearer token |
| 403 | Scan action on a serve started without authorization / 未授权启动的 serve 收到扫描动作 |
| 500 | Infrastructure failure (action panicked / IO broken) / 基础设施级失败 |

### Redaction & caps / 脱敏与上限

- `http` redacts `set-cookie`, `cookie`, `authorization`, `proxy-authorization` to `{"redacted":true,"length":N}`. / 这四个敏感头被脱敏。
- `netscan` caps at 4096 hosts and 4096 ports; oversized CIDRs are rejected with 400 **before** any packet is sent. / 上限 4096 主机 × 4096 端口，超限 CIDR 在发包前即被 400 拒绝。
- `device` issues at most 4 HTTP probes (`http_max`, default 2). / `device` 最多发起 4 次 HTTP 探测。

## Example session / 示例会话

```bash
# start with scan actions unlocked / 以解锁扫描动作的方式启动
neton serve --port 8753 --yes-i-have-permission

# health
curl http://127.0.0.1:8753/health
# -> {"ok":true}

# action catalog
curl http://127.0.0.1:8753/invoke-actions

# read-only observation
curl -s -X POST http://127.0.0.1:8753/invoke -H 'Content-Type: application/json' \
     -d '{"params":{"action":"arp"}}'

# authorized subnet scan
curl -s -X POST http://127.0.0.1:8753/invoke -H 'Content-Type: application/json' \
     -d '{"params":{"action":"netscan","cidr":"192.168.1.0/24"}}'

# on a serve started WITHOUT --yes-i-have-permission:
# -> 403 {"error":"scan action 'netscan' requires the server to be started with --yes-i-have-permission"}

# token-protected server / token 保护的服务
neton serve --port 8753 --token sekrit
curl -H 'Authorization: Bearer sekrit' http://127.0.0.1:8753/invoke-actions
```

## CLI exit codes / CLI 退出码

| Command / 命令 | Codes / 退出码 |
| --- | --- |
| observation commands / 观测类命令 | `0` success / `2` error |
| scan commands (authorized) / 扫描命令（已授权） | `0` (findings are data, not errors / 结果是数据不是错误) |
| scan commands without authorization / 未授权的扫描命令 | `2` (notice on stderr / stderr 输出授权声明) |
| no command, stdin empty / 无命令且 stdin 为空 | `0` (prints help / 打印帮助) |
