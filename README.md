# 茄盒（Snagbox）

茄盒是一款面向 AI Agent 的本机应用流量采集与分析工具。它把指定程序产生的网络请求保存为可查询的数据，并把数据表、字段含义、关联关系和只读 SQL 查询能力交给 Agent。

茄盒不替 Agent 预先规定“登录分析”“风控分析”或其他固定分析套路。用户提出问题后，Agent 自己把问题转成查询，依据每次查询的结果决定下一步，直到证据足以回答问题。

## 设计理念：Agent 理解问题并编排分析

用户通常会问“这个程序登录时调用了哪些接口”“错误请求集中在哪个时间段”或“这几条请求是不是同一条操作链”。用户不需要先知道表名、字段名或 SQL。

Agent 在茄盒提供的数据和说明之上，承担两项工作：

- **翻译用户意图**：把自然语言问题转成可以执行的 SQL 查询。
- **控制分析流程**：根据查询结果决定接下来要查什么、如何筛选和关联、是否需要分批读取或绘图，并判断何时已有足够证据。

一次分析可以这样逐步进行：

1. Agent 通过 MCP 查看有哪些数据表和记录。
2. Agent 查看相关表的字段定义，并按需读取关联关系说明。
3. Agent 根据用户的问题编写只读 SQL，查询需要的记录或统计结果。
4. Agent 检查结果；如果信息不足，就调整条件、关联字段或时间范围，再发起下一次查询。
5. 需要呈现统计趋势时，Agent 把查询结果交给茄盒的绘图接口。
6. Agent 综合查询证据，用用户能理解的方式解释结果。

茄盒提供分析所需的**资料、关联说明和工具**；具体分析路径由 Agent 按问题动态组织。这样用户可以提出未被茄盒预先写成模板的新问题，Agent 也不必把整份数据库一次性加载到内存中。

```text
用户的问题
    ↓
AI Agent：理解意图 → 编写 SQL → 查询 → 检查证据 → 决定下一步
    ↕ MCP
茄盒：流量数据 + 表结构和字段说明 + 关联关系 + 只读查询 + 图表渲染
```

## 茄盒提供什么

| 能力 | 说明 |
|---|---|
| 指定程序的流量采集 | 通过 Ghost Proxifier 将目标程序的流量路由到茄盒本机代理。 |
| 结构化本地数据 | 将可识别的 HTTP、DNS、连接和代理层消息记录到 SQLite。 |
| 数据说明 | 通过 MCP 提供表清单、字段定义和跨表关联关系，帮助 Agent 正确理解数据。 |
| 灵活查询 | 通过受限的只读 SQL 接口，让 Agent 自己筛选、统计和关联数据。 |
| 图表呈现 | Agent 决定统计口径并查询结果，再调用绘图接口呈现结果。 |

茄盒不内置固定的业务分析流程，也不替 Agent 自动认定某两条记录存在因果关系。字段匹配、时间接近或端点相同都只是分析线索，结论需要 Agent 结合数据判断。

## 数据与关联

| 数据表 | 内容 | 常见关联线索 |
|---|---|---|
| `http` | HTTP 请求、响应、请求头和响应头；请求体、响应体以实体字节保存。 | `uid`、采集批次、域名、URL、引用/跳转字段、时间。 |
| `conn` | 代理观察到的连接元数据、端点和时间信息。 | `uid`、采集批次、客户端/服务端端点、时间。 |
| `dns` | 被茄盒观察到的 DNS 查询与响应。 | 域名、解析地址、时间；需注意 DNS 与连接的对应关系并非总能保证。 |
| `tcp_message` / `udp_message` | mitmproxy 提供的代理层 TCP 数据块或 UDP datagram。 | `uid`、方向、时间、对应连接元数据。 |
| `capture_session` | 一次采集批次的元数据。 | `session_id`。 |
| `capture_control` | 当前采集状态。 | 控制采集写入行为，不是网络事件表。 |

完整字段定义见 [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md)，关联字段及其含义见 [`DATA_RELATIONSHIPS.md`](DATA_RELATIONSHIPS.md)。Agent 可通过 MCP 的 `get_data_relationships` 按需读取关联说明。

**数据边界：**

- 茄盒记录的是代理层观察到的流量，不是网卡层的原始数据包。
- HTTPS 在根证书受信任且成功解密时，HTTP 内容可进入 `http` 表；未解密时，TLS 数据块以加密内容保存在 `tcp_message`，连接元数据保存在 `conn`。
- 根证书不能解开应用自身加密的内容，也不能保证绕过证书固定。
- 请求头、Cookie 和请求/响应体可能含有令牌、密码或个人数据。请妥善保护本地数据库，分享前检查内容。

## MCP 接口

### Agent 分析数据

| 接口 | 用途 |
|---|---|
| `list_event_tables` | 列出事件表、用途和记录数。 |
| `describe_event_table(table_name)` | 查看表字段、类型及约束。 |
| `get_data_relationships` | 读取跨表关联说明和注意事项。 |
| `query_events_sql(sql, row_limit=100)` | 执行只读 `SELECT` / `WITH` 查询，返回行数和内容受限。 |
| `render_chart(...)` | 将 Agent 查询得到的数据渲染成图表；统计口径由 Agent 的 SQL 决定。 |

### Agent 控制采集和目标程序

| 接口 | 用途 |
|---|---|
| `start_listening` | 开始采集新流量。 |
| `suspend_listening` | 暂停写入新流量，保留已有数据。 |
| `resume_listening` | 恢复采集。 |
| `stop_listening` | 停止采集并清除已有事件数据；代理和 MCP 服务继续运行。 |
| `list_snagbox_processes` | 查看经 `snagbox` 上游节点路由的 Ghost 进程组。 |
| `start_snagbox_program(target_path, arguments="")` | 按目标程序路径复用已有进程组，必要时才新建，并通过 `snagbox` 节点启动。 |
| `stop_snagbox_program(process_name)` | 停止经 `snagbox` 节点路由且匹配名称的目标进程。 |
| `get_upstream_http_proxy` / `set_upstream_http_proxy(...)` | 查看或设置茄盒的可选链式 HTTP 上游代理。 |
| `get_https_inspection_status` | 查看根证书信任状态和 HTTPS 检查状态。 |
| `install_https_root_certificate` / `uninstall_https_root_certificate` | 安装或卸载当前用户的茄盒根证书，并切换 HTTPS 检查状态。 |

## 工作方式

```text
目标程序
  → Ghost Proxifier 按进程路由
  → 茄盒本机代理（mitmproxy）
  → addon 写入 SQLite
  → MCP 将数据说明、只读查询和图表渲染交给 AI Agent
  → Agent 依据用户问题迭代查询并解释结果
```

Ghost Proxifier 提供通用的进程路由和控制能力；茄盒负责流量采集、数据保存和面向 Agent 的分析接口。

## 安装与开发

茄盒作为 Ghost Proxifier 插件运行。插件包构建脚本位于 [`plugin-package/build_plugin.ps1`](plugin-package/build_plugin.ps1)，插件清单位于 [`plugin-package/manifest.json`](plugin-package/manifest.json)。MCP 服务也可以单独启动：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python mcp_server.py --init --transport streamable-http --host 127.0.0.1 --port 8000
```

数据库、关联和插件接入的补充说明：

- [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md)：SQLite 表结构
- [`DATA_RELATIONSHIPS.md`](DATA_RELATIONSHIPS.md)：表之间的关联关系
- [`PLUGIN_INTEGRATION_PLAN.md`](PLUGIN_INTEGRATION_PLAN.md)：Ghost Proxifier 插件接入说明

## 许可

茄盒源码采用 [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0)，完整条款见 [`LICENSE`](LICENSE)。它允许非商业目的使用、修改和分发源码，不授予他人商业使用权。茄盒版权持有人保留其拥有版权的代码的商业化权利；本项目不向第三方提供商业授权。

这符合“公开源码、仅由版权持有人商业化”的目标，但**不属于 OSI 定义的开源软件**：开源定义要求许可证不能禁止商业领域使用。因此更准确的说法是“源码公开、非商业许可”，而不是“开源许可”。

如接受外部代码贡献，贡献者仍可能保留其贡献的著作权。若要由茄盒版权持有人独立授予整套软件的商业许可，需要在接受贡献前约定版权转让或足以支持再许可的贡献者协议（CLA）。
