# Snagbox 数据关联关系

## 关联关系类型

1. **批次关联**：记录属于同一次采集。
2. **Flow ID 关联**：记录属于同一个 mitmproxy flow。
3. **网络端点关联**：记录使用相同的协议、客户端和服务端地址。
4. **应用字段关联**：域名、HTTP 引用或跳转字段指向同一主机/请求。
5. **时序关联**：比较两条或多条记录的先后、间隔或时间重叠。
6. **CEP 事件模式关联**：在时间窗口内匹配一组事件模式，例如 A 后跟 B、A 重复多次、A 后未出现 B。它分析的是事件序列，不只是两条记录时间接近。
7. **相似关联**：按多个特征寻找相似记录，例如请求路径、头字段、状态码和长度相近。相似表示“行为像”，不表示同一对象或因果关系。

## 表和字段的关联

| 关系类型 | 表和字段 | 关联说明 |
|---|---|---|
| 批次 | `capture_session.session_id` ↔ `conn/http/dns/tcp_message/udp_message.session_id` | 同一次采集；不表示同一条流 |
| Flow ID | `conn.uid` ↔ `http.uid` | HTTP hook 使用同一 Flow ID 写入两表 |
| Flow ID | `conn.uid` ↔ `tcp_message.uid` / `udp_message.uid` | 数据块外键指向对应传输 flow 的连接记录 |
| Flow ID | `dns.uid` ↔ `conn.uid` | **当前不保证关联**：DNS hook 不保证创建同 UID 的 `conn` 记录 |
| 网络端点 | `conn/http/dns` 的 `proto`、`id.orig_h`、`id.orig_p`、`id.resp_h`、`id.resp_p` | 端点相同是候选关联；应结合采集批次和时间。数据块表通过 `uid` 回到 `conn` 查端点 |
| DNS 到 HTTP | `dns.query` / `dns.answers` ↔ `http.host` / `http.id.resp_h` | 域名、解析地址相符时是候选关联；需结合批次和时间 |
| HTTP 请求间 | `http.referrer`、响应头 `Location` ↔ 其他 HTTP 行的 `host` / `uri` | 页面引用或跳转线索，属于候选关联 |
| 时序 | 各事件表的 `ts`；TCP/UDP 的 `message_index`、`from_client` | 比较事件先后、间隔和重叠；时间接近本身不证明因果 |
| CEP 事件模式 | 事件类型（表）、`ts`，以及用于分组的 `session_id`、`uid`、端点或域名 | 可描述 A→B、重复次数、时间窗口和缺失事件；当前没有专用 CEP 引擎，Agent 可基于查询结果分析已采集事件 |
| 相似 | HTTP 的 `method`、`host`、`uri`、头字段、状态码、长度；TCP/UDP 的长度、方向和数据块顺序 | Agent 可按选定特征比较或分组；当前没有保存相似度分数，body 内容也不在 HTTP 事件行中 |

`uid` 标识 mitmproxy flow，不等同于真实网卡连接。端点、域名和时间关系都是候选关系，不能单独证明因果。
