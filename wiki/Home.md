# Neton Wiki / Neton 维基

**Neton** — Structured local network observation and diagnostics for AI agents around the [BIT](https://github.com/yxpil/bit) ecosystem: host overview, interfaces, listening ports, DNS, TCP probes, HTTP summaries, plus **authorized LAN discovery** (ARP table, subnet device discovery, port scanning, per-device fingerprinting). Everything as JSON — an agent can *read* the network instead of scraping text.

**Neton** —— 面向 [BIT](https://github.com/yxpil/bit) 生态 AI 智能体的结构化本机网络观测与诊断工具：主机概览、网卡、监听端口、DNS、TCP 探活、HTTP 摘要，以及**经授权的局域网发现**（ARP 表、子网设备发现、端口扫描、单设备指纹分析）。全部输出 JSON，让智能体"看懂"网络，而不是解析人读的文本。

- Repo / 仓库: <https://github.com/yxpil/Neton>
- Releases / 发行版: <https://github.com/yxpil/Neton/releases>
- Binary name / 二进制名: `neton`
- Default port / 默认端口: `8753`

> **⚠️ Scan commands (`netscan` / `portscan` / `device`) only touch networks you own or are authorized to test. / 扫描类命令只用于你拥有或已获授权的网络。**

---

## Install / 安装

Grab a per-platform binary from the [latest release](https://github.com/yxpil/Neton/releases/latest) (`tar.gz` for macOS/Linux, `zip` for Windows), or:

从 [最新 Release](https://github.com/yxpil/Neton/releases/latest) 下载对应平台二进制（macOS/Linux 为 `tar.gz`，Windows 为 `zip`），或：

```bash
cargo install --git https://github.com/yxpil/Neton
```

## Usage / 使用

```bash
# observation — read-only, no root / 观测类 —— 只读、无需 root
neton info                                    # hostname, OS, arch, outbound IP / 主机概览
neton interfaces                              # NICs: IPv4/IPv6, MAC, status / 网卡
neton ports                                   # listening TCP + bound UDP with pid / 监听端口
neton dns example.com                         # system resolver lookup / 系统解析
neton ping 192.168.1.1 --port 443             # TCP connect probe (no ICMP) / TCP 探活
neton probe "h1:80,h2:443"                    # concurrent multi-target probe / 批量探活
neton http http://192.168.1.1/                # status, timing, headers (redacted), preview
neton arp                                     # ARP/neighbor table + MAC vendor lookup / ARP 表 + 厂商

# scans — require explicit authorization / 扫描类 —— 需显式授权
neton netscan 192.168.1.0/24 --yes-i-have-permission          # discover LAN devices / 局域网设备发现
neton portscan 192.168.1.1 --ports 1-1024 --yes-i-have-permission  # TCP connect port scan
neton device 192.168.1.1 --yes-i-have-permission              # one device: MAC vendor, rDNS, ports, HTTP fingerprint

# HTTP API (BIT Remote compatible) / HTTP API（兼容 BIT Remote）
neton serve --port 8753                        # scan actions answer 403
neton serve --port 8753 --yes-i-have-permission # scan actions enabled
```

Every subcommand accepts `--json` (default) and `--pretty`; piped stdin JSON merges over CLI args (stdin wins — the BIT exec contract):

所有子命令支持 `--json`（默认即 JSON）与 `--pretty`；管道 stdin 的 JSON 会合并覆盖 CLI 参数（stdin 优先，即 BIT exec 契约）：

```bash
echo '{"host":"example.com"}' | neton dns
```

Exit codes / 退出码: `0` success / 成功 · `2` error or missing scan authorization / 出错或未授权。

## Scan authorization / 扫描授权

```bash
neton portscan 192.168.1.1 --yes-i-have-permission
# or / 或者: NETON_I_HAVE_PERMISSION=yes neton portscan 192.168.1.1
```

- CLI without the acknowledgement exits with code **2** and explains the flag on stderr. / CLI 未带确认时以退出码 **2** 结束，stderr 说明所需标志。
- `neton serve` only exposes the scan actions when started with `--yes-i-have-permission`; otherwise `/invoke` answers **403** for them. / serve 只有以该标志启动时才暴露扫描动作，否则 `/invoke` 返回 **403**。
- `arp` is read-only neighbor-table observation and needs no acknowledgement. / `arp` 是只读观测，无需确认。
- Scans are TCP-connect only: no raw sockets, no SYN floods, no root. `netscan` caps at 4096 hosts × 4096 ports. / 扫描仅基于 TCP connect：无原始套接字、无 SYN 洪水、无需 root；`netscan` 上限 4096 主机 × 4096 端口。

## BIT integration / BIT 集成

Three ways / 三种方式:

1. **CLI (exec runtime)** — BIT spawns `neton <subcommand> --json`, sends `params` JSON via stdin, reads JSON from stdout. Interpreter `code` example: `portscan 192.168.1.1 --ports 80,443 --yes-i-have-permission` (the AI must obtain the user's authorization **before** passing the confirmation flag / AI 必须先取得用户授权再传确认标志).
2. **Remote tool** — run `neton serve`, register URL `http://127.0.0.1:8753/invoke`; BIT POSTs `{"tool_id":"...","tool":"...","invoked_by":"...","params":{"action":"info"}}`. Scan actions need the serve itself started with `--yes-i-have-permission`.
3. **Plain REST** — `GET /health`, `GET /invoke-actions`, `POST /invoke` (see [Protocol](Protocol)).

Typical scenario / 典型场景: "why is the printer unreachable?" → `neton arp` shows whether it is on the neighbor table, `neton device 192.168.1.50 --yes-i-have-permission` reveals vendor/ports/HTTP banner, `neton ping 192.168.1.1` confirms the gateway — all as JSON the agent can reason over.

"打印机怎么连不上？" → `neton arp` 看邻居表、`neton device 192.168.1.50` 看厂商/端口/HTTP 指纹、`neton ping 192.168.1.1` 确认网关 —— 全部是智能体可推理的 JSON。

## FAQ

**Q: Why does `netscan` exit with code 2 before doing anything? / 为什么 `netscan` 什么都没做就退出码 2？**
The authorization gate is working. Confirm the target is yours / covered by written permission, then add `--yes-i-have-permission` (or set `NETON_I_HAVE_PERMISSION=yes`).

这是授权门控在生效。确认目标为自有资产或已获书面授权后，加 `--yes-i-have-permission`（或设置 `NETON_I_HAVE_PERMISSION=yes`）即可。

**Q: Does scanning need root? / 扫描需要 root 吗？**
No. Everything is plain TCP connect + OS tables (`arp`/`ip neigh`), no raw sockets, no promiscuous mode.

不需要。全部基于普通 TCP connect 与系统表（`arp`/`ip neigh`），无原始套接字、不进混杂模式。

**Q: What is `common` in `--ports common`? / `--ports common` 是哪些端口？**
A preset of 40 top TCP ports. You can also pass lists (`80,443`) or ranges (`1-1024`).

40 个常用 TCP 端口的预设。也可以传列表（`80,443`）或区间（`1-1024`）。

**Q: How reliable is the `device` type guess? / `device` 的设备类型推测可靠吗？**
It is informational only — derived from MAC vendor, open ports and page titles. It is a hint, never a certainty.

仅供参考 —— 由 MAC 厂商、开放端口与页面标题推导，只是提示，不是结论。

**Q: Are sensitive HTTP headers leaked? / 敏感 HTTP 响应头会泄露吗？**
No. `set-cookie`, `cookie`, `authorization`, `proxy-authorization` are redacted to `{"redacted":true,"length":N}`.

不会。`set-cookie`、`cookie`、`authorization`、`proxy-authorization` 被脱敏为 `{"redacted":true,"length":N}`。

---

Part of the [BIT](https://github.com/yxpil/bit) ecosystem.
