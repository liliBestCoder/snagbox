# Snagbox SQLite schema

数据库由 [`database.py`](C:/Users/admin/Desktop/NetTraceMVP/database.py) 的 `SCHEMA` 自动初始化。默认文件是 `data/nettrace.sqlite`；插件模式将它放在 Ghost 分配的插件私有 `dataDir` 中。SQLite 使用 WAL 与外键约束。

## 表关系

```text
capture_session 1 ── * conn 1 ── * tcp_message
        │                    ├── * udp_message
        │                    └── 0..1 http (uid = conn.uid)
        └── * dns (same capture_session; no guaranteed conn.uid row)
capture_control.active_session_id ──(逻辑指向)── 当前 capture_session
```

`capture_control` 是采集开关的运行状态表。`list_event_tables` 默认隐藏它；它不承载网络事件。

## `capture_control` — 采集状态（单行）

| 字段 | 类型 | 约束 | 用途 |
|---|---|---|---|
| `singleton_id` | INTEGER | 主键，必须为 `1` | 固定单例键 |
| `state` | TEXT | 非空；`listening` / `suspended` / `stopped` | 只有 `listening` 会写入新事件 |
| `active_session_id` | TEXT | 可空 | 当前采集 session；停止采集不会关闭 Snagbox 服务 |
| `updated_at` | REAL | 非空 | 最近一次开关更新时间，Unix 秒 |

`stop_listening` 把 `state` 设为 `stopped` 并清除已有事件行，但不关闭 MCP、mitmproxy 或代理转发。Ghost 停用插件才会结束服务。

## `capture_session` — 采集批次

| 字段 | 类型 | 约束 | 用途 |
|---|---|---|---|
| `session_id` | TEXT | 主键 | 随机生成的批次 ID |
| `started_at` | REAL | 非空 | 开始时间，Unix 秒 |
| `ended_at` | REAL | 可空 | 结束时间；活动 session 为 NULL |
| `capture_label` | TEXT | 非空 | 用户给本轮采集的标签 |
| `notes` | TEXT | 可空 | 批次备注 |
| `mitmproxy_version` | TEXT | 可空 | 创建批次时的 mitmproxy 版本 |

## `conn` — 连接元数据（Zeek conn 风格）

主键 `uid` 由 mitmproxy flow ID 派生。HTTP flow 在保存响应或错误记录时创建对应 `conn`；未解密 HTTPS 在 TCP flow 开始时创建 `conn`，并将 TLS 字节写入 `tcp_message`。因此监听期间完整观察到并被采集的 HTTP/HTTPS flow 都应有 `conn` 行；尚未完成且尚未报错的 HTTP 请求可能还没有落库记录。

注意：这里的 `conn` 是代理观察到的 flow 记录，不是网卡层的 TCP socket 清单。HTTP keep-alive 上的多个请求可能分别对应多个 HTTP flow/`conn` 行；不能据此推断底层 TCP socket 数量。

| 字段 | 类型 | 用途 |
|---|---|---|
| `uid` | TEXT PK | Snagbox 本地连接 ID |
| `ts` | REAL NOT NULL | 连接开始时间，Unix 秒 |
| `id.orig_h` / `id.orig_p` | TEXT / INTEGER | 发起端地址 / 端口 |
| `id.resp_h` / `id.resp_p` | TEXT / INTEGER | 响应端地址 / 端口 |
| `proto` | TEXT NOT NULL | `tcp` 或 `udp` |
| `service` | TEXT | 识别的应用协议，可空 |
| `duration` | REAL | 连接持续秒数 |
| `orig_bytes` / `resp_bytes` | INTEGER | 两个方向保存的代理层 payload 字节数 |
| `conn_state` | TEXT | 连接结束状态（如 `SF`、`OTH`） |
| `local_orig` / `local_resp` | INTEGER | 端点是否为本机（0/1，可空） |
| `missed_bytes` | INTEGER | mitmproxy 未提供的字节数，可空 |
| `history` | TEXT | 扩展历史字段，当前可空 |
| `orig_pkts` / `orig_ip_bytes` | INTEGER | 发起方向 IP 包数 / IP 层字节数；代理层不可得时为 NULL |
| `resp_pkts` / `resp_ip_bytes` | INTEGER | 响应方向 IP 包数 / IP 层字节数；代理层不可得时为 NULL |
| `session_id` | TEXT NOT NULL | 采集批次外键 |
| `capture_label` | TEXT NOT NULL | 写入时的标签快照 |
| `error` | TEXT | 连接错误信息，可空 |

索引：`idx_conn_ts(ts)`、`idx_conn_orig(id.orig_h,id.orig_p)`、`idx_conn_resp(id.resp_h,id.resp_p)`。

## `http` — HTTP 请求/响应元数据

主键 `uid` 是 HTTP flow 标识，并与对应的 `conn.uid` 相同；`session_id` 外键指向采集批次。关联细节见 [DATA_RELATIONSHIPS.md](C:/Users/admin/Desktop/NetTraceMVP/DATA_RELATIONSHIPS.md)。

| 字段 | 类型 | 用途 |
|---|---|---|
| `uid` | TEXT PK | 对应连接 ID |
| `ts` | REAL NOT NULL | HTTP 请求开始时间，Unix 秒 |
| `id.orig_h` / `id.orig_p` | TEXT / INTEGER | 客户端地址 / 端口 |
| `id.resp_h` / `id.resp_p` | TEXT / INTEGER | 服务端地址 / 端口 |
| `trans_depth` | INTEGER | HTTP 事务序号，可空 |
| `method` | TEXT | 请求方法 |
| `host` | TEXT | 请求 Host |
| `uri` | TEXT | 请求路径 |
| `referrer` | TEXT | Referer |
| `version` | TEXT | HTTP 版本 |
| `user_agent` | TEXT | User-Agent |
| `request_headers` | TEXT | 请求头；JSON 编码的 `[名称, 值]` 数组，保留重复字段，可空 |
| `response_headers` | TEXT | 响应头；JSON 编码的 `[名称, 值]` 数组，保留重复字段，可空 |
| `request_body_len` / `response_body_len` | INTEGER | 请求体 / 响应体长度 |
| `request_body` | BLOB | 请求体字节；可空 |
| `response_body` | BLOB | 响应体字节；可空 |
| `status_code` | INTEGER | HTTP 状态码 |
| `status_msg` | TEXT | 状态描述 |
| `tags` | TEXT | JSON 编码的 mitmproxy tags |
| `session_id` | TEXT NOT NULL | 采集批次外键 |
| `capture_label` | TEXT NOT NULL | 写入时的标签快照 |
| `error` | TEXT | HTTP flow 错误，可空 |

索引：`idx_http_ts(ts)`、`idx_http_host(host)`。

请求头和响应头存储为 mitmproxy 解析后的字段，不是原始 wire 字节；重复字段（例如多个 `Set-Cookie`）按出现顺序分别保留。请求体和响应体以 mitmproxy 提供的实体字节存入 BLOB；它们不含 HTTP chunk framing，也不保证等于网卡上的完整 wire 字节。未解密的 HTTPS 不会进入 `http` 表，而会以加密 TLS 字节块写入 `tcp_message`，并关联 `conn.uid`；信任 Snagbox 根证书且解密成功后，HTTPS 请求/响应体写入 `http` 表。头和正文都可能包含凭据、Cookie、聊天内容或其他敏感数据，数据库应按敏感数据保护。

## `dns` — DNS 查询/响应元数据

主键 `uid` 与 `conn.uid` 关联；`session_id` 外键指向采集批次。

| 字段 | 类型 | 用途 |
|---|---|---|
| `uid` | TEXT PK | 对应 flow/连接 ID |
| `ts` | REAL NOT NULL | DNS 时间，Unix 秒 |
| `id.orig_h` / `id.orig_p` | TEXT / INTEGER | 查询端地址 / 端口 |
| `id.resp_h` / `id.resp_p` | TEXT / INTEGER | DNS 服务端地址 / 端口 |
| `proto` | TEXT | DNS 传输协议 |
| `trans_id` | INTEGER | DNS transaction ID |
| `rtt` | REAL | 请求往返秒数 |
| `query` | TEXT | 查询域名 |
| `qclass` / `qclass_name` | INTEGER / TEXT | 查询类别代码 / 名称 |
| `qtype` / `qtype_name` | INTEGER / TEXT | 查询类型代码 / 名称 |
| `rcode` / `rcode_name` | INTEGER / TEXT | 响应码 / 名称 |
| `AA` / `TC` / `RD` / `RA` / `Z` | INTEGER | DNS 标志位 |
| `answers` | TEXT | JSON 编码的答案列表 |
| `TTLs` | TEXT | JSON 编码的 TTL 列表 |
| `rejected` | INTEGER | 查询是否被拒绝（0/1） |
| `session_id` | TEXT NOT NULL | 采集批次外键 |
| `capture_label` | TEXT NOT NULL | 写入时的标签快照 |
| `error` | TEXT | DNS flow 错误，可空 |

索引：`idx_dns_ts(ts)`、`idx_dns_query(query)`。

## `tcp_message` / `udp_message` — 传输层原始数据块

两表字段一致，分别存 TCP 字节块和 UDP datagram。一个 mitmproxy TCP message 不等同于一个 TCP segment 或应用协议消息。

| 字段 | 类型 | 约束 / 用途 |
|---|---|---|
| `message_id` | INTEGER | 自增主键 |
| `uid` | TEXT NOT NULL | 外键指向 `conn.uid` |
| `session_id` | TEXT NOT NULL | 外键指向 `capture_session.session_id` |
| `ts` | REAL NOT NULL | 数据块时间，Unix 秒 |
| `message_index` | INTEGER NOT NULL | 同一 flow 内序号 |
| `from_client` | INTEGER NOT NULL | 方向：1 为客户端发出，0 为服务端发出 |
| `content` | BLOB NOT NULL | 原始 payload 字节 |
| `content_len` | INTEGER NOT NULL | payload 字节数 |

索引：`idx_tcp_message_uid(uid,message_index)`、`idx_udp_message_uid(uid,message_index)`。

## 写入保护与分析边界

- `capture_conn_insert_guard` / `capture_conn_update_guard`、`capture_http_insert_guard`、`capture_dns_insert_guard`、`capture_tcp_message_insert_guard`、`capture_udp_message_insert_guard`：当 `capture_control.state != 'listening'` 时忽略新事件写入。
- `conn.orig_pkts`、`conn.resp_pkts` 及 IP 层字节数来自真实网卡/内核层统计，mitmproxy 的代理层数据无法提供，因此通常为 NULL；不能把消息块数量冒充网络包数。
- 采集关闭期间，代理仍可转发，但不会再把新事件写入数据库。HTTPS 明文可见性取决于客户端是否信任 mitmproxy CA；应用层自加密仍不可解密。
- MCP 的 `query_events_sql` 只读，并限制行数、响应大小与查询时长。BLOB 默认只返回长度和短 hex 预览。
