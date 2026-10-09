# snagbox 设计稿

版本：0.2（MVP 初版）  
日期：2026-10-03  
状态：已按本文实现初版；UDP 经 Ghost 到 mitmproxy 的端到端链路仍待单独验证。

## 1. 目标

做一个本机运行的协议逆向数据采集 MVP：将选定应用的流量导入 mitmproxy，由 Python addon 把事件和原始传输数据写入 SQLite；再启动一个 MCP Server，让 AI 自主发现数据表、查看字段并执行只读 SQL 查询。

核心验证问题：给 AI 多次交互产生的 TCP/UDP 样本和结构化事件后，它能否通过查询与对比，帮助用户推测未知协议的消息边界和字段规律。

MVP 不承诺自动破解协议。加密、压缩、混淆和缺少足够样本时，AI 只能提出待验证假设。

## 2. 产品形态

第一版是一个独立的 Windows Python 项目，不是 Ghost 插件，也不修改 Ghost 核心。Ghost 用于把目标进程的流量导向本机 mitmproxy；mitmproxy addon 采集数据；MCP Server 通过 stdio 给本机 AI 客户端连接。

```text
目标应用
   │
   ▼
Ghost Proxifier（按进程导流）
   │ HTTP CONNECT / SOCKS5
   ▼
本机 mitmproxy + Python addon
   ├── Zeek 风格事件 ──────┐
   └── 原始 TCP/UDP 数据块 ─┤
                            ▼
                       SQLite 数据库
                            ▲
                            │ 只读查询
                     Python MCP Server
                            ▲
                            │ stdio
                            ▼
                       AI 客户端
```

采集数据只保存在本机。首版不上传云端，也不要求 AI 直接读取文件系统。

## 3. 数据采集范围

### 3.1 首版支持

- mitmproxy 可见的 TCP flow：方向、时间、端点、原始数据块。
- mitmproxy 可解析的 HTTP flow：请求方法、主机、URI、版本、状态码及长度等 Zeek 风格字段。
- mitmproxy 可见的 DNS flow：查询名、类型、响应码、答案等 Zeek 风格字段。
- mitmproxy 可见的 UDP flow：按 datagram 保存方向、时间、端点和原始字节。
- 用户启动采集时提供一个 `capture_label`，用于标记当前目标程序或实验轮次。

HTTP 请求体和响应体默认不作为普通事件字段展开。原始 TCP/UDP 数据会作为 BLOB 保存；可通过 MCP SQL 取长度、十六进制片段或定位样本记录。

### 3.2 不在首版承诺

- 从 mitmproxy 反推出目标进程 PID。经过公共本机代理后，mitmproxy 通常只看到本机代理连接；首版通过用户设置的 `capture_label` 标记单个实验。
- 自动识别未知协议的消息边界、字段语义、加密或压缩算法。
- TCP 报文级数据（IP/TCP header、sequence number、ACK、重传）。mitmproxy addon 接收的是代理层的 TCP 字节块，不是原始网卡 PCAP。
- 自动重放、篡改或注入流量。
- HTTPS pinning 绕过。若客户端不信任 mitmproxy CA，TLS 内容不可解密；自定义协议自身加密时仍只能分析密文。

## 4. SQLite 数据模型

事件表采用 Zeek 日志的按事件类型分表思路，字段尽量贴近 Zeek。原始传输内容放在两个扩展表，不伪装成 Zeek 标准日志。

### 4.1 `capture_session`

本地采集批次：`session_id`、`started_at`、`ended_at`、`capture_label`、`notes`、`mitmproxy_version`。

### 4.2 `conn`

以 Zeek `conn.log` 为参照：

- `uid`, `ts`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`
- `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`
- `local_orig`, `local_resp`, `missed_bytes`, `history`
- `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`
- 扩展字段：`session_id`, `capture_label`, `error`

SQLite 列名保留 Zeek 的点号形式；SQL 中用双引号引用，例如 `SELECT "id.orig_h" FROM conn`。

mitmproxy 无法提供真实的 TCP segment 数量和 IP 层字节数。这些字段留为 SQL NULL，不用应用层数据块数量冒充网络包数。`orig_bytes` / `resp_bytes` 根据实际保存的 TCP 字节块或 UDP datagram payload 累计；仅有 HTTP 解析事件、没有原始传输 hook 的连接保留 NULL。

### 4.3 `http`

参照 Zeek `http.log`：`uid`, `ts`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `trans_depth`, `method`, `host`, `uri`, `referrer`, `version`, `user_agent`, `request_headers`, `response_headers`, `request_body_len`, `response_body_len`, `request_body`, `response_body`, `status_code`, `status_msg`, `tags`，以及 `session_id`、`capture_label` 扩展字段。请求头和响应头以保留重复字段的 JSON 键值对数组存储；请求体和响应体以 BLOB 保存 mitmproxy 提供的实体字节。没有受信任 CA 时，HTTPS 保持 TLS 旁路，原始加密字节进入 `tcp_message`，并与 `conn.uid` 关联；信任 CA 且解密成功时，HTTP 元数据和正文进入 `http` 表。头和正文可能包含 Cookie、认证凭据或其他敏感内容。

### 4.4 `dns`

参照 Zeek `dns.log`：`uid`, `ts`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `trans_id`, `rtt`, `query`, `qclass`, `qclass_name`, `qtype`, `qtype_name`, `rcode`, `rcode_name`, `AA`, `TC`, `RD`, `RA`, `Z`, `answers`, `TTLs`, `rejected`，以及批次扩展字段。

### 4.5 `tcp_message`（扩展表）

每条记录保存一个 mitmproxy TCPFlow 数据块：`uid`, `session_id`, `ts`, `message_index`, `from_client`, `content`（BLOB）, `content_len`。

重要：TCPFlow 数据块边界来自代理读取，不保证等于目标协议消息边界。未信任 Snagbox 根证书的 HTTPS 隧道会以加密 TLS 数据块形式进入此表；这些数据不能直接当作 HTTP 明文解析。查询时可按连接和方向拼接字节流；AI 应把每个块的边界视为采集元数据，而非协议边界。

### 4.6 `udp_message`（扩展表）

每条记录保存一个 UDP datagram：`uid`, `session_id`, `ts`, `message_index`, `from_client`, `content`（BLOB）, `content_len`。UDP datagram 边界保留，不跨 datagram 拼成字节流。

### 4.7 标识和关联

MVP 使用 mitmproxy flow ID 派生本地 `uid`。该 ID 仅用于本次采集库内关联，不宣称与 Zeek UID 算法兼容。每个连接/事件带 `session_id`，便于跨实验轮次比较。

## 5. Mitmproxy 接入方式

1. mitmproxy 在 `127.0.0.1` 监听本机代理端口。
2. Ghost 的上游节点配置为本机代理地址；目标程序仍由 Ghost 按进程规则导流。
3. addon 订阅 mitmproxy 的 TCP、UDP、HTTP、DNS 生命周期 hook；hook 只把记录放入有界内存队列，由单独的 SQLite 写入线程落库，避免在代理事件回调中执行数据库 I/O。
4. SQLite 开启 WAL，后台写入线程单写；MCP 查询使用独立只读连接。队列上限为 8192 条记录和 64 MiB 原始数据，达到上限时为保护代理时延会丢弃新采集记录，并在 mitmproxy 关闭时报告丢弃数量。

Ghost 当前支持 HTTP CONNECT 和 SOCKS5 上游。TCP 端到端转入 mitmproxy regular proxy 的方案可先做验证；非 HTTP TCP 需要启用/配置 mitmproxy generic TCP 支持。

### UDP 先行验证项

Ghost 对 UDP 的上游转发依赖 SOCKS5 UDP ASSOCIATE。mitmproxy 的常规/ SOCKS5 接入模式与其通用 UDP 模式并非同一条代理路径，因此不能先假设 Ghost → mitmproxy 的 UDP 链路能工作。

实现前先做一个小型端到端验证：Ghost 目标进程发出 UDP echo 流量，确认 mitmproxy 的 `udp_message` hook 能收到并保存 datagram。若链路不通，首版先保留 UDP 数据模型与 addon hook，TCP MVP 独立完成；再评估兼容适配器或另一种 UDP 导流方式。

## 6. MCP 接口

MCP Server 使用 Python MCP SDK 的 stdio 或 Streamable HTTP transport，提供表发现/字段说明/只读 SQL、采集开关、按 Ghost 目标名称启停等工具。监听状态保存在 SQLite 的内部 `capture_control` 表中，addon 轮询该状态；状态暂停或停止时，代理仍转发流量，只是不记录。数据库触发器也会阻止停止/暂停状态下的写入。插件模式额外通过 Ghost 专用 API 管理 snagbox 节点和受管进程。

### `list_event_tables`

返回用户数据库中的事件表名、简短描述和记录数。仅列出应用表，不返回 SQLite 内部表。

### `describe_event_table(table_name)`

返回指定表的字段名、SQLite 类型、是否可空、主键标记和字段说明。只接受白名单中的现有表名。

### `query_events_sql(sql, row_limit=100)`

在事件数据库上执行一条只读 SQL，返回列名、行数据和是否截断。允许 SELECT / WITH 查询；连接使用 SQLite read-only 与 `query_only` 防护。默认最多返回 100 行，绝对上限 500 行，并限制单次响应大小和查询执行时间。BLOB 默认用长度与短 hex 预览返回；用户可用 SQLite `hex()`、`substr()`、`length()` 主动选择需要的字节范围。

SQL 查询工具保留 AI 探索数据的自由度；表发现与字段说明不预设分析流程。

### 监听控制工具

- `start_listening`: 开始写入采集数据。
- `suspend_listening`: 暂停记录，保留已有数据。
- `resume_listening`: 恢复记录。
- `stop_listening`: 停止写入新事件并清除已有事件数据；Snagbox/MCP 服务和代理转发继续运行。Ghost 停用插件才会关闭服务。

## 7. 项目目录草案

```text
snagbox/
  DESIGN.md                 设计文档
  addon.py                  mitmproxy addon 和事件采集 hook
  database.py               SQLite schema、写入和连接管理
  mcp_server.py             SQLite 查询、采集控制和 Ghost 目标管理 MCP 工具
  requirements.txt          mitmproxy、MCP SDK
  README.md                 安装、启动和 Ghost 配置步骤
  data/                     本机数据库（加入 .gitignore）
```

## 8. 验收标准

1. addon 启动后自动创建 SQLite schema。
2. 目标 TCP 流量经过 Ghost → mitmproxy 后，`conn` 和 `tcp_message` 可查到同一 uid 的双向字节样本。
3. 可解析的 HTTP 和 DNS 流量分别写入 `http`、`dns` 表。
4. mitmproxy 实际收到 UDP flow 时，`udp_message` 保存每个独立 datagram；Ghost 到 mitmproxy 的 UDP 路由单独记录验证结果。
5. MCP 客户端能探索表结构、执行只读 SQL，并控制采集状态与 snagbox 受管目标。
6. 对未知表、写 SQL、超时查询和过量结果有明确错误/截断响应。
7. 关闭并重新启动后数据仍保留在 SQLite。

## 9. 主要风险与产品边界

- **明文可见性**：HTTPS MITM 需要客户端信任 mitmproxy CA；pinning 或应用层加密会阻止明文查看。
- **进程归属**：mitmproxy 默认无法知道 Ghost 透明导流前的 PID。首版采用逐个目标程序实验和手工 `capture_label`。
- **数据量与隐私**：payload 可能包含凭据、聊天内容或令牌。数据库仅本机存储；README 明确提示敏感性，并提供清库步骤。后续可加入采集大小上限和自动清理。
- **协议推断质量**：AI 的推断要附带样本 uid、方向、偏移和原始字节证据；不把猜测写成事实。
- **代理兼容性**：应用可能不兼容 HTTP CONNECT、代理证书或 mitmproxy 对连接时序的改变。

## 10. 官方接口参考

- mitmproxy [Event Hooks](https://docs.mitmproxy.org/stable/api/events.html)：TCP/UDP/HTTP/DNS 事件 hook。
- mitmproxy [TCPFlow API](https://docs.mitmproxy.org/stable/api/mitmproxy/tcp.html)：TCP 数据块和任意分块边界说明。
- mitmproxy [UDPFlow API](https://docs.mitmproxy.org/stable/api/mitmproxy/udp.html)：UDP datagram 模型。
- mitmproxy [Proxy Modes](https://docs.mitmproxy.org/stable/concepts/modes/) 与 [Protocol Support](https://docs.mitmproxy.org/stable/concepts/protocols/)：代理接入方式及通用 TCP/UDP 支持边界。
- Zeek [conn.log](https://docs.zeek.org/en/master/reference/logs/conn.html)、[http.log](https://docs.zeek.org/en/master/reference/logs/http.html)、[dns.log](https://docs.zeek.org/en/master/reference/logs/dns.html)：标准事件字段参照。
