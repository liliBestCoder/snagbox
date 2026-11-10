# Snagbox 数据关联关系

## 关联关系类型

1. **批次关联**：记录属于同一次采集。
2. **Flow ID 关联**：记录属于同一个 mitmproxy flow。
3. **网络端点关联**：记录使用相同的协议、客户端和服务端地址。
4. **进程与 Target 归属关联**：网络连接反查出的物理 PID、exe 路径，及向上 5 层回溯匹配到的 Ghost Target 业务归属。
5. **应用字段关联**：域名、HTTP 引用或跳转字段指向同一主机/请求。
6. **时序关联**：比较两条或多条记录的先后、间隔或时间重叠。
7. **CEP 事件模式关联**：在时间窗口内匹配一组事件模式，例如 A 后跟 B、A 重复多次、A 后未出现 B。它分析的是事件序列，不只是两条记录时间接近。
8. **相似关联**：按多个特征寻找相似记录，例如请求路径、头字段、状态码和长度相近。相似表示“行为像”，不表示同一对象或因果关系。

---

## 表和字段的关联

| 关系类型 | 表和字段 | 关联说明 |
|---|---|---|
| **Target 归属** | `conn.target_id` ↔ `get_status.targets[].targetId` | 识别网络连接属于哪个 Ghost 受管目标（如 `chrome.exe` 等） |
| **根进程关联** | `conn.root_pid` ↔ `get_status.targets[].pid` | 多进程架构软件（如 Chrome Network Service）向上追溯归属于 Ghost 启动的主进程 |
| **进程跨表联查** | `http.uid` ↔ `conn.uid` (查 `conn.pid`, `conn.process_name`, `conn.target_id`) | HTTP 请求关联到真实发包进程及其归属的 Target |
| 批次 | `capture_session.session_id` ↔ `conn/http/dns/tcp_message/udp_message.session_id` | 同一次采集；不表示同一条流 |
| Flow ID | `conn.uid` ↔ `http.uid` | HTTP hook 使用同一 Flow ID 写入两表 |
| Flow ID | `http.uid` ↔ `filter_hits.flow_uid` | 命中的 Filter 动作与原始 HTTP 记录强关联；可溯源被篡改/Mock的原始端点 |
| Filter 规则 | `filter_registry.name` ↔ `filter_hits.filter_name` | 命中记录归属的具体动态 Filter 规则名称 |
| Flow ID | `conn.uid` ↔ `tcp_message.uid` / `udp_message.uid` | 数据块外键指向对应传输 flow 的连接记录 |
| Flow ID | `dns.uid` ↔ `conn.uid` | **当前不保证关联**：DNS hook 不保证创建同 UID 的 `conn` 记录 |
| 网络端点 | `conn/http/dns` 的 `proto`、`id.orig_h`、`id.orig_p`、`id.resp_h`、`id.resp_p` | 端点相同是候选关联；应结合采集批次和时间。数据块表通过 `uid` 回到 `conn` 查端点 |
| DNS 到 HTTP | `dns.query` / `dns.answers` ↔ `http.host` / `http.id.resp_h` | 域名、解析地址相符时是候选关联；需结合批次和时间 |
| HTTP 请求间 | `http.referrer`、响应头 `Location` ↔ 其他 HTTP 行的 `host` / `uri` | 页面引用或跳转线索，属于候选关联 |
| 时序 | 各事件表的 `ts`；TCP/UDP 的 `message_index`、`from_client` | 比较事件先后、间隔和重叠；时间接近本身不证明因果 |
| CEP 事件模式 | 事件类型（表）、`ts`，以及用于分组的 `session_id`、`uid`、端点或域名 | 可描述 A→B、重复次数、时间窗口和缺失事件；当前没有专用 CEP 引擎，Agent 可基于查询结果分析已采集事件 |
| 相似 | HTTP 的 `method`、`host`、`uri`、头字段、状态码、长度；TCP/UDP 的长度、方向和数据块顺序 | Agent 可按选定特征比较或分组；当前没有保存相似度分数，body 内容也不在 HTTP 事件行中 |

---

## 进程与 Ghost Target 字段说明 (`conn` 表)

Snagbox 在连接建立瞬间通过客户端源端口（`id.orig_p`）反查 Windows 内核 TCP 表，并自动向上遍历至多 5 层父进程树匹配 Ghost 受管 Target：

- **`conn.pid`** (INTEGER): 发起该网络连接的**直接物理进程 ID**（例如 Chrome 的网络服务子进程 PID）。
- **`conn.process_name`** (TEXT): 发起该连接的进程可执行文件名（例如 `chrome.exe`）。
- **`conn.process_path`** (TEXT): 发起该连接的进程完整可执行文件绝对路径。
- **`conn.root_pid`** (INTEGER): 向上追溯至多 5 层后，匹配到的 Ghost Target **根进程 ID**（若未受管或 5 层内未匹配则为 NULL）。
- **`conn.root_process_name`** (TEXT): 匹配到的 Ghost Target 根进程名称。
- **`conn.target_id`** (TEXT): 归属的 Ghost Target 唯一标识符（例如 `DF0215C7-2ECF-4A50-831E-FBBA4A3B6BD6`，与 `get_status` 的 `targets` 对应）。

---

## 典型 SQL 联合查询指南 (给 AI / Agent)

在使用 `query_events_sql` 工具时，Agent 可充分利用上述字段进行多维归因分析：

### 1. 查询指定 Target（如 Chrome）的全部 HTTP 请求与状态码
```sql
SELECT 
    datetime(h.ts, 'unixepoch', 'localtime') AS req_time,
    h.method,
    h.host,
    h.uri,
    h.status_code,
    c.pid AS worker_pid,
    c.root_pid,
    c.target_id
FROM http h
JOIN conn c USING (uid)
WHERE c.target_id = 'DF0215C7-2ECF-4A50-831E-FBBA4A3B6BD6'
ORDER BY h.ts DESC
LIMIT 50;
```

### 2. 统计各 Target 与独立进程发起的连接数与流量消耗
```sql
SELECT 
    COALESCE(c.root_process_name, c.process_name, 'Unknown') AS app_name,
    c.target_id,
    COUNT(DISTINCT c.uid) AS total_connections,
    COUNT(h.uid) AS total_http_requests,
    SUM(COALESCE(c.orig_bytes, 0) + COALESCE(c.resp_bytes, 0)) AS total_traffic_bytes
FROM conn c
LEFT JOIN http h USING (uid)
GROUP BY c.target_id, app_name
ORDER BY total_traffic_bytes DESC;
```

### 3. 排查未受管外部进程（未匹配 Target 的外部直接调用）
```sql
SELECT 
    c.pid,
    c.process_name,
    c.process_path,
    COUNT(*) AS conn_count
FROM conn c
WHERE c.target_id IS NULL AND c.pid IS NOT NULL
GROUP BY c.pid, c.process_name, c.process_path
ORDER BY conn_count DESC;
```
