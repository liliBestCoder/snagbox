# 茄盒（Snagbox）

茄盒（Snagbox）是一个面向 AI Agent 的本机应用流量采集与分析工具。它把指定程序的网络流量经过本机代理，保存为可查询的数据，再通过 MCP 把数据结构、关联线索、只读 SQL 查询和图表绘制能力交给 Agent。

茄盒不预设“登录分析”“接口统计”等固定分析模板。Agent 根据用户的问题自行探索数据、编写 SQL、分批查询和归纳结果；茄盒提供数据与绘图工具，不替 Agent 决定分析结论。

## 它解决什么问题

普通抓包工具通常面向人工逐条查看。茄盒的目标是让用户把某个应用的真实网络行为交给 AI Agent 分析，例如：

- 查看某次运行访问了哪些域名、HTTP 页面、脚本和 API。
- 找出一组请求之间的字段关联、跳转关系或时间先后关系。
- 按域名、状态码、时间区间或请求类型统计数据，再生成图表。
- 对某个应用的请求、响应和连接记录做进一步筛选与对比。

茄盒只采集经过它的目标程序流量，不是全网卡抓包器。目标程序由 Ghost Proxifier 按进程路由到茄盒；不经过该路由的流量不会出现在茄盒数据库中。

## 工作流程

```text
用户 / AI Agent
    │ 通过 MCP 要求启动程序、查询数据或绘制图表
    ▼
Ghost Proxifier ──按进程路由──> 茄盒本机 HTTP 代理
    │                                  │
    │ 通用注入、进程查询与控制          ├─ mitmproxy 解析可识别的协议
    │                                  └─ addon.py 写入 SQLite
    ▼                                           │
目标程序                                      MCP 查询接口
                                                │
                                    Agent 分批查询、关联、统计和解释
```

启用 Ghost 插件后，茄盒会启动本机代理和 MCP 服务，并通过 Ghost 的通用配置接口确保存在名为 `snagbox` 的 HTTP 上游节点。目标程序经该节点进入茄盒。Agent 可以通过 MCP 启动目标程序、检查已经由该节点路由的进程组、停止匹配进程，再查询采集结果。

数据分析流程由 Agent 根据问题动态组织：先查看表和字段，再读取关联说明，编写只读 SQL 查询；需要图表时，把查询结果交给绘图接口。绘图接口只负责呈现数据，不负责替 Agent 做聚合或分析。

## 采集内容和记录含义

| 流量类型 | 记录方式 | 说明 |
|---|---|---|
| 明文 HTTP | `http` + 对应的 `conn` | 保存请求/响应字段、重复请求头、响应头，以及请求体和响应体实体字节。 |
| HTTPS，未信任茄盒根证书 | `tcp_message` + `conn` | TLS 内容仍是加密字节，只能分析连接端点、方向、时序和数据块长度等外层信息。 |
| HTTPS，已信任茄盒根证书且成功解密 | `http` + 对应的 `conn` | 保存可解析的 HTTP 请求/响应字段和正文。证书固定等机制可能阻止解密。 |
| TCP / UDP flow | `tcp_message` / `udp_message` + `conn` | 保存 mitmproxy 提供的代理层数据块；UDP 端到端链路仍需按具体 Ghost 路由方式验证。 |
| DNS flow | `dns` | 仅在 DNS flow 到达 mitmproxy addon 时记录；不能假设每条 DNS 记录都有同 UID 的 `conn`。 |

几个重要边界：

- `conn` 是代理观察到的 flow 元数据，不是网卡层的 TCP socket 清单。HTTP keep-alive 上的多个请求可能分别形成多个 HTTP flow 和 `conn` 行。
- `tcp_message` 保存的是代理层数据块，不是网卡数据包，也不保证边界对应完整的应用层消息。
- HTTP 请求体和响应体以 BLOB 保存的是实体字节，不包含 HTTP chunk framing，也不保证等于线路上的完整字节序列。
- HTTPS 没有受信任的茄盒根证书时不会进入 `http` 表；此时 TLS 仍加密，但隧道数据会作为 TCP flow 记录。
- 根证书只允许茄盒尝试 TLS 中间人解密，不会解开应用自身的二次加密，也无法绕过证书固定。

请求头、Cookie、请求体、响应体可能包含密码、访问令牌和个人内容。数据库应按敏感数据保护，不要在未检查的情况下分享采集文件。

## Agent 可使用的 MCP 能力

### 查询与分析

| 接口 | 用途 |
|---|---|
| `list_event_tables` | 列出事件表、用途和记录数。 |
| `describe_event_table(table_name)` | 查看指定表的列名、SQLite 类型、非空约束和主键。 |
| `get_data_relationships` | 按需读取跨表关联说明、关联强度、注意事项和 SQL 示例。 |
| `query_events_sql(sql, row_limit=100)` | 执行单条只读 `SELECT` / `WITH` 查询；响应行数最多 500，返回内容也有大小限制。 |
| `render_chart(...)` | 将 Agent 查询所得数据渲染为 PNG；支持折线、柱状、堆叠柱状、散点和直方图，最多 10,000 行。 |

茄盒不内置 CEP 引擎、相似度算法或固定统计报表。Agent 可以用 SQL 进行筛选、分组、关联和统计；需要复杂时序或事件模式分析时，也可以分批查询并继续分析。数据库就在本地，不要求一次把整库加载到 Agent 内存中。

### 采集控制

| 接口 | 行为 |
|---|---|
| `start_listening` | 开始记录新流量；代理继续转发。 |
| `suspend_listening` | 暂停写入新记录，但保留已有数据和代理服务。 |
| `resume_listening` | 恢复记录新流量。 |
| `stop_listening` | 停止记录并清除已有事件数据；茄盒、MCP 和代理转发继续运行。 |

### Ghost 进程与代理设置

| 接口 | 行为 |
|---|---|
| `list_snagbox_processes` | 列出经 `snagbox` 上游路由的 Ghost 目标进程组。 |
| `start_snagbox_program(target_path, arguments="")` | 按绝对可执行文件路径查找已有目标组；已有且运行中则复用，已停止则重新启动，仅在不存在时创建新组。新建或复用时使用 DOT DNS 模式。 |
| `stop_snagbox_program(process_name)` | 仅停止经 `snagbox` 节点路由、且名称匹配的进程树。 |
| `get_upstream_http_proxy` | 查询茄盒是否配置了链式 HTTP 上游；不返回密码。 |
| `set_upstream_http_proxy(proxy_url, username="", password="")` | 设置或清除链式 HTTP 代理。路由为“目标程序 → Ghost → 茄盒 → 可选 HTTP 代理”；已有连接可能需要重连。 |

### HTTPS 根证书

| 接口 | 行为 |
|---|---|
| `get_https_inspection_status` | 查询当前用户是否信任茄盒根证书，并同步 HTTPS 拦截模式。 |
| `install_https_root_certificate` | 将茄盒根证书安装到当前 Windows 用户的受信任根证书存储，并启用 HTTPS 检查。 |
| `uninstall_https_root_certificate` | 移除茄盒自己的根证书并切换为 HTTPS 透传模式，避免浏览器遇到不受信任的拦截证书。 |

## 安装和运行

### 作为 Ghost 插件运行（推荐）

1. 安装 Ghost Proxifier，并在插件中心启用本地插件或开发者模式。
2. 在 Ghost 插件权限弹窗中审阅并授予插件申请的权限：`config.read`、`config.write`、`target.launch`、`target.control`。
3. 安装并启用茄盒插件。启用后，插件会启动 mitmproxy 代理、MCP Streamable HTTP 服务，并确保 Ghost 中存在指向 `127.0.0.1:8080` 的 `snagbox` 上游节点。
4. 将 Ghost MCP 服务地址配置给 AI Agent。插件运行时会提供本机 MCP 地址；以插件界面显示的地址为准。
5. 告诉 Agent 要分析的程序。Agent 解析该程序的主可执行文件路径后调用 `start_snagbox_program`，再通过其他 MCP 接口采集和分析。

Ghost 插件权限是通用能力授权。特别是 `config.write` 允许插件提交 Ghost 配置；`target.launch` 和 `target.control` 允许启动、查看和控制目标程序。请在授权弹窗中确认权限用途。

Ghost 选择的 Python 解释器需要预先安装项目依赖。Ghost 不会替插件安装 `mitmproxy`、MCP SDK、Uvicorn 或 Matplotlib。

### 构建本地 Ghost 插件包

在 PowerShell 中执行：

```powershell
.\plugin-package\build_plugin.ps1 -GhostRepo "C:\path\to\ghost-proxifier-ui"
```

构建结果写入 `plugin-package/dist/`，默认文件名为 `com.ghostproxifier.snagbox-<版本>.gpkg`。本地开发包未签名；请通过 Ghost 支持的本地安装/开发者流程安装。插件清单位于 [`plugin-package/manifest.json`](plugin-package/manifest.json)，构建脚本位于 [`plugin-package/build_plugin.ps1`](plugin-package/build_plugin.ps1)。

### 独立开发运行

需要 Python 3.12 或更新版本。在项目根目录的 PowerShell 中安装依赖：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

终端启动 mitmproxy 代理和采集 addon：

```powershell
mitmdump --mode regular --listen-host 127.0.0.1 --listen-port 8080 `
  --set nettrace_db=./data/nettrace.sqlite `
  --set nettrace_label=target-app `
  -s .\addon.py
```

另开终端启动 MCP Streamable HTTP 服务：

```powershell
python .\mcp_server.py --db .\data\nettrace.sqlite --transport streamable-http --host 127.0.0.1 --port 8000
```

MCP 地址为 `http://127.0.0.1:8000/mcp`。手动开发时，需要自行把目标程序或测试客户端配置到 `127.0.0.1:8080`。也可以使用 stdio MCP：

```powershell
python .\mcp_server.py --db .\data\nettrace.sqlite
```

独立运行模式不自动调用 Ghost 注入 API，也不自动创建 Ghost 上游节点。

## 数据库和关联说明

默认数据库位置是 `data/nettrace.sqlite`；Ghost 插件模式使用 Ghost 分配的插件私有数据目录。主要数据表如下：

| 表 | 内容 |
|---|---|
| `capture_session` | 采集批次与运行元信息。 |
| `conn` | mitmproxy flow 的端点、协议和连接状态等元数据。 |
| `http` | HTTP 请求/响应元数据、头字段及正文实体字节。 |
| `dns` | 到达 addon 的 DNS 查询和响应信息。 |
| `tcp_message` | TCP flow 的代理层数据块。 |
| `udp_message` | UDP flow 的代理层数据块。 |
| `capture_control` | 采集状态控制行，不是网络事件表。 |

字段和索引见 [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md)。跨表关联包括批次、Flow ID、网络端点、应用字段、时序、CEP 事件模式和相似特征；具体字段、关联强度和限制见 [`DATA_RELATIONSHIPS.md`](DATA_RELATIONSHIPS.md)。查询跨表数据前，Agent 应先读取关联说明，不应把候选关联误当成因果证明。

只读 SQL 示例（Zeek 风格字段名需用双引号）：

```sql
SELECT uid, "id.resp_h", "id.resp_p", orig_bytes, resp_bytes
FROM conn
ORDER BY ts DESC
LIMIT 20;
```

查看 TCP 数据块时，可只取有限字节，避免返回大 BLOB：

```sql
SELECT uid, message_index, from_client, content_len,
       hex(substr(content, 1, 64)) AS first_bytes
FROM tcp_message
ORDER BY message_id DESC
LIMIT 20;
```

## 运行特性与限制

- 数据库由后台写入线程处理，mitmproxy hook 不同步等待每条数据库写入。写队列有容量上限；数据库跟不上时新事件可能被丢弃，插件关闭时会报告丢弃数。
- `query_events_sql` 只接受 `SELECT` 或 `WITH`，有查询时限、行数上限和响应体积限制。直接读取 BLOB 时会返回长度和有限的十六进制预览。
- 图表接口只接收 Agent 已查询的数据；聚合、时间分桶、过滤和序列整理由 Agent 通过 SQL 完成。
- 不同 mitmproxy 模式对 UDP 的支持不同。Ghost SOCKS5 UDP ASSOCIATE 到 mitmproxy UDP flow 的端到端链路尚未验证；当前不要把 UDP 视为已完整支持的 Ghost 采集路径。
- 茄盒是 MVP，不会自动推断未知协议结构、绕过证书固定、解密应用层二次加密，也不提供流量重放或修改能力。

## 目录结构

```text
.
├── addon.py                         # mitmproxy 流量采集钩子
├── database.py                      # SQLite schema、写入队列和数据库访问
├── mcp_server.py                    # MCP 工具与只读 SQL、图表能力
├── plugin_main.py                   # Ghost 插件入口、代理/MCP 生命周期和桥接
├── plugin-package/
│   ├── manifest.json                # Ghost 插件清单和权限申请
│   └── build_plugin.ps1             # 本地 .gpkg 构建脚本
├── DATABASE_SCHEMA.md               # 数据表与字段说明
├── DATA_RELATIONSHIPS.md             # 跨表关联说明
├── DESIGN.md                         # 设计说明
└── PLUGIN_INTEGRATION_PLAN.md        # Ghost 插件接入说明与实现记录
```
