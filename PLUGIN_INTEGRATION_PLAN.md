# snagbox 接入 Ghost Proxifier 插件中心：改造计划

审计日期：2026-10-09  
审计对象：`C:\Users\admin\Desktop\NetTraceMVP` 与 `C:\Users\admin\Desktop\ghost-proxifier-ui-snagbox`  
状态：实现稿；Ghost 仅提供通用 API 与权限授权，Snagbox MCP 组合这些 API 实现专属流程

## 1. 结论与建议

建议把 snagbox 做成 Ghost 插件中心可安装、可启停、可嵌入界面的**独立进程插件**。插件进程负责与 Ghost 完成握手、提供本机管理页面，并在进程内编排 mitmproxy 与 MCP 服务；mitmproxy 继续负责实际 TCP/HTTP/DNS 采集，SQLite 和 MCP 查询能力继续保留。

插件化不会让 Ghost 插件 API 变成抓包 API。Ghost 不提供网络 payload；原始 TCP/HTTP/DNS 仍由 mitmproxy addon 采集。Ghost 只提供通用配置读写、进程发现、注入启动、进程统计与控制 API。插件在清单中申请 Ghost 定义的通用权限类别，用户在启用弹窗逐项授权；Snagbox MCP 自己用通用 API 按名称确保上游、选择节点启动目标，并按节点过滤进程列表和停止操作。

推荐先走 Ghost 的**本地开发者模式**完成可运行 MVP，不先做官方商店发布。功能跑通、依赖和包体积可控后，再讨论签名和上架。

### 推荐运行拓扑

```text
Ghost Proxifier
  ├─ ghost_plugin_host.exe（监督 snagbox 插件进程）
  │    ├─ snagbox 插件入口（握手、嵌入 UI、生命周期管理）
  │    ├─ mitmproxy DumpMaster + addon.py（采集 TCP/HTTP/DNS，写 SQLite）
  │    └─ MCP Streamable HTTP 服务（供外部 AI 客户端查询）
  └─ 被管目标进程
       └─ Ghost 进程路由 → 自动确保的 snagbox HTTP CONNECT 上游 → snagbox mitmproxy
```

Ghost 插件宿主用 Windows Job Object 管插件进程。插件停用或宿主关闭时，插件应先优雅停止 mitmproxy、MCP 和 UI；超时后宿主会终止插件进程。目标程序被路由到本机 snagbox 上游时，插件停用会让该上游不可用，界面和安装说明必须明确提示这一点。

## 2. 两边当前实现情况

### snagbox 现状

- [`addon.py`](C:/Users/admin/Desktop/NetTraceMVP/addon.py)：mitmproxy addon。创建采集 session，订阅 TCP、UDP、HTTP、DNS hooks；通过有界队列把记录交给 SQLite 写线程；`done()` 中停止控制轮询、结束 session 并等待写队列落盘。
- [`database.py`](C:/Users/admin/Desktop/NetTraceMVP/database.py)：SQLite schema、单写线程和只读连接。目录由数据库构造器创建，数据库文件位置可以通过启动参数传入 addon。
- [`mcp_server.py`](C:/Users/admin/Desktop/NetTraceMVP/mcp_server.py)：提供 Streamable HTTP 或 stdio MCP transport；插件模式动态选择 MCP 端口并将数据库路径绑定到 Ghost 私有 `dataDir`。`stop_listening` 停止记录并清除已有事件行，但不关闭服务。
- 旧 `start_snagbox.bat` 已由插件进程内的 `DumpMaster` 与 MCP 服务取代并移除；独立调试仍可在终端手动启动。
- README 同时记录了 SOCKS5 listener（1080）和 HTTP regular listener（8080）的不同手动路径；Ghost 自身支持的是把目标程序流量经配置的 HTTP CONNECT 上游转发。正式插件路径应以可验证的 HTTP CONNECT → mitmproxy regular listener 方案为基线，不沿用当前 batch 中的 SOCKS5 inbound 作为默认方案。
- UDP hooks 已写，但 Ghost SOCKS5 UDP ASSOCIATE 到 mitmproxy UDP flow 的端到端链路仍标为待验证；插件 MVP 应明确先交付 TCP/HTTP/DNS，不把 UDP 写成已支持。

### Ghost 插件机制

- 每个插件是独立进程，由 `ghost_plugin_host.exe` 拉起、监督、有限次重启和收尾；不是 DLL，也不在 Ghost 主进程中执行。
- 插件从 stdin 读取一行握手 JSON，向 stdout 写**恰好一行** JSON 回执并 flush。成功回执可以包含 `uiUrl`；握手后不能再向 stdout 写日志。握手 token 只在 stdin，不得写日志、命令行或磁盘。
- `manifest.json` 指定 `entry`、`runtime`、`ui.embedded` 和 `permissions`。`.py` 入口需要系统 Python；Ghost 不会自动安装 Python 包。`ui.embedded: true` 时插件自己开 loopback HTTP 服务并回报 `http://127.0.0.1:<port>/...`。
- Host 会把插件进程放入 Job Object；停止通过握手提供的命名 Windows event 请求，约 3 秒后仍未退出会硬终止 Job。插件要显式等待握手里的 `stopEvent` 并完成清理。
- 插件 UI iframe 与 Ghost 控制接口不同源，拿不到 `window.GHOST_TOKEN`，不能从 UI 直接请求 Ghost API。插件服务必须自己提供 UI 后端；若要访问 Ghost API，由插件进程使用自己的 token 和清单权限调用。
- 原始 payload 不从 Ghost 插件 API 获取。Snagbox 申请 `config.read`、`config.write`、`target.launch`、`target.control`；用户在 Ghost 启用弹窗授权。它们分别用于读配置、保存去重后的节点配置、发现/注入启动程序、读取统计并停止选定节点上的进程。
- `.gpkg` 是 store-only 未压缩包，最大 64 MiB。`gpkg.py pack` 会采集源目录里几乎所有文件，只跳过 VCS 目录和根 `.github`；`.gitignore` 不会替打包器排除文件。当前源树的 `.venv` 和 `data` 必须从包构建输入中排除。
- 开发者模式可以从本地 `.gpkg` 安装未签名插件；插件安装后默认停用，启用时仍走权限确认。官方上架还要签名、发布描述和注册表流程，属于后续阶段。

## 3. 目标范围与非目标

### MVP 目标

1. 在 Ghost 插件中心本地安装、启用、停用、卸载 snagbox。
2. 插件中心内嵌 snagbox 状态和基本操作页面。
3. 插件进程内启动 mitmproxy `DumpMaster` 与 MCP 服务；停用插件时才关闭服务并 flush 数据库。`stop_listening` 停止采集、清掉历史事件行，但 Snagbox、MCP 与代理转发继续运行。
4. 插件启动时先确认 mitmproxy listener 就绪，再调用 Ghost 专用配置 API，按 `snagbox` 名称去重并校正到 `127.0.0.1:8080`。
5. MCP Streamable HTTP 可继续供兼容的 AI 客户端连接，查询数据行为保持只读边界。
6. 用户已有数据可选择迁移进插件的私有数据目录，不把数据打进插件包。

### 明确不包含

- 从 Ghost API 获取或重建原始 payload。
- 附着到任意已运行进程。`start_snagbox_program` 先按目标可执行文件路径和 snagbox 节点查询 Ghost 进程组：已有运行组则直接返回，已有停止组则复用原组启动；仅没有匹配组时才调用注入 API 创建组。`stop_snagbox_program` 仅停止 Ghost 识别为 snagbox 目标的进程树。
- 第一版承诺 UDP 端到端采集、TLS pinning 绕过、未知协议自动识别或自动重放。
- 第一版直接上官方商店。

## 4. 需要先解决的设计问题

### 4.1 上游与 listener 模式

插件先启动并确认 mitmproxy HTTP regular listener，然后通过 Ghost 通用 `GET /config` 与 `POST /save-config` API 按名称检查、校正并去重 `snagbox` 上游；新节点不自动激活。目标程序通过通用 `POST /inject` 提交所选节点 ID。进程查看与停止通过通用 `/process-stats`、`/api/kill-process-tree` 完成，MCP 侧仅选择 nodeId 为 snagbox 的目标和子进程。

不要把当前 batch 的 `--mode socks5` listener 直接认定为正确接入：它是客户端连接到 snagbox 的 SOCKS5 listener；Ghost 的核心数据面文档描述的是 Ghost 连到配置的 HTTP CONNECT upstream。两者方向与代理协议需要明确区分。

验证内容：

- Ghost 的 HTTP 上游节点能否指向 `127.0.0.1:<snagbox-port>` 并由 mitmproxy regular mode 接收 CONNECT。
- Ghost 自身建立到回环上游的连接不会被再次导流，且不会形成代理循环。
- 普通 HTTP、可解密 TLS、任意 TCP 各用一个最小样例验证。
- UDP 单独列为后续实验；未实际收到 mitmproxy UDP hooks 前不显示“UDP 已采集”。

### 4.2 Python 与第三方依赖

现有项目依赖 `mitmproxy`、MCP Python SDK 和 Uvicorn。Ghost 的 `runtime.kind: "python"` 只检查系统 Python 版本并选择解释器，不会安装 requirements。启用前要把依赖预装到 Ghost 选择的 Python；缺依赖时握手失败并显示清晰原因。

构建脚本只从白名单 stage 打包插件源码。根目录下 `.venv`、`.gitignore` 不会阻止文件进入包；当前 `data` 有 SQLite/WAL，不能放入 `.gpkg`。当前不 vendor 依赖，由用户预装，避免启用时联网安装和包体积失控。

依赖决策顺序：

1. 当前选择 `runtime: python`，用户将依赖安装到 Ghost 选用的 Python；启用插件不暗中联网 pip install。
2. 若后续要面向普通用户分发，再评估 vendor 依赖或独立安装器，并验证 `.gpkg` ≤ 64 MiB。
3. `upstream.connect` 若未来需要，必须重新评估为 x64 `.exe` 入口；本方案不为获得该权限而改成 exe。

### 4.3 插件数据与已有数据库

插件运行时把 SQLite 放到握手 `dataDir`（升级保留）；不要写到插件包目录，也不要将 repo 的 `data/` 放入 `.gpkg`。Ghost 卸载插件会删除插件私有数据目录，因此要在 UI/文档说明卸载数据策略，MVP 至少提供卸载前导出/备份路径。

如果迁移当前 `data/nettrace.sqlite`：先停止所有 mitmproxy/MCP 实例，执行一致性 checkpoint 或用 SQLite Backup API 复制，校验后再放入 `dataDir`。不要直接复制仍在 WAL 写入的主文件；不要覆盖或清除现有库。启动时只迁移一次并留迁移标记。

### 4.4 控制语义

MCP `start_listening` / `suspend_listening` / `resume_listening` 保留。`stop_listening` 停止新增记录并清除既有事件 rows。还要区分：

- **暂停采集**：mitmproxy 继续转发，SQLite 不再记新事件（复用现有 `suspended` 状态）。
- **恢复采集**：恢复写事件。
- **关闭 snagbox 服务**：停止 MCP server 与 mitmproxy，flush 数据；Ghost 上游暂时不可用。
- **清除捕获数据**：独立、带二次确认的破坏性操作，不与停用插件或结束 session 绑定。

插件禁用/卸载/退出 Ghost 会走服务关闭路径。不要为了保持 listener 活着而在插件进程退出后留下孤儿服务；Host Job Object 也会清理子进程。

## 5. 目标实现设计

### 5.1 插件入口和进程编排

独立插件入口 `plugin_main.py`，不把 Ghost 握手逻辑塞进 mitmproxy addon。入口职责：

1. 通过 `GHOST_PLUGIN_ID` 判断是否由 Ghost 启动；独立开发模式可以复用当前命令行入口。
2. hosted 模式只读取一行 JSON 握手，验证 `v`、`token`、`apiBase`、`stopEvent`、`dataDir` 类型与必填项。
3. 先解析配置、准备 dataDir、在进程内启动 mitmproxy `DumpMaster` 与 MCP/UIs 服务，等待 listener 就绪并调用 Ghost 上游 ensure API，再回一行 `{"v":1,"ok":true,"uiUrl":"http://127.0.0.1:<port>/..."}` 并 flush。全过程须在 10 秒握手超时内。
4. 内部服务线程不写插件 stdout；插件自身仅输出一行握手回执，之后不再写 stdout。
5. 监听握手 `stopEvent`。收到后停止 MCP、关闭 UI，再调用 mitmproxy `DumpMaster.shutdown()`，让 addon `done()` drain SQLite 队列并结束 session；超时由 Host 杀插件进程。
6. 代理或 MCP 初始化异常时握手回 `ok:false`；不申请 `log.write`，不忙循环重启，不隐藏依赖或端口错误。

不要自己按 PID 拼 stop event 名称；必须打开握手给的名字。宿主启动 `.py` 时实际进程可能是 Python interpreter，SDK 明确要求用握手事件。

### 5.2 UI 与控制 API

新增简洁的插件专属本机 HTTP 服务：

- 仅监听 `127.0.0.1`；随机选择 UI 端口，成功绑定后再回报 `uiUrl`。
- UI iframe 与 Ghost 控制接口不同源，不依赖 Ghost 页面 token，不从浏览器直接请求 `23551` 控制接口。
- 首版嵌入 UI 显示代理 endpoint、MCP endpoint 和 MCP 工具说明；start/pause/resume/stop 通过 MCP 调用。
- UI server 参考 Ghost `plugin-events-viewer` 的 Host/Origin/CSP/随机路径设计；本机服务不应假定“loopback 就只有自己能访问”。状态读取可低敏，状态变更需要校验请求来源与方法。
- 页面明确标注监听协议/端口、启动时创建的 Ghost `snagbox` 节点、代理服务关闭时依赖该节点的目标程序会连接失败、TLS 明文取决于 CA 信任。

清单申请 `config.read`、`config.write`、`target.launch` 与 `target.control`；Ghost 在启用弹窗中向用户显示权限说明并按选择授予。不申请 `events.read.data`、`upstream.connect` 或 `log.write`。Ghost 的事件数据不会提供 snagbox 所需的原始 payload。

### 5.3 mitmproxy 和 MCP 子服务

- 插件进程内运行 mitmproxy `DumpMaster`，使用与 Ghost HTTP CONNECT upstream 匹配的 regular mode；未信任根证书时对忽略的 TLS tunnel 启用 `show_ignored_hosts`，以 TCP 字节块采集加密数据并写入 `conn`/`tcp_message`，不把普通 HTTP 改成原始 TCP。数据库和 mitmproxy 配置均使用握手 `dataDir`。
- 数据库路径只取自 `dataDir`；capture label 由 UI 的实验名/目标标签传入，避免在插件里猜目标 PID（Ghost 插件 API 不给 `targets.json`）。
- MCP 继续用 Streamable HTTP，绑定 loopback 动态端口；内嵌 UI 显示实际 MCP endpoint。提供三个进程控制动作：`list_snagbox_processes`、`start_snagbox_program` 与 `stop_snagbox_program`；程序发现由 start 工具内部处理。
- HTTP listener 与 MCP listener 端口可配置且冲突时要报告明确错误；默认端口冲突不能导致握手成功但服务不可用。
- MCP 查询仍只读、行数/响应大小/超时限制继续生效。`stop_listening` 停止记录并删掉已有事件 rows，但 Snagbox、MCP 与转发仍运行；只有 Ghost 停用插件才关闭服务。
- mitmproxy CA 只在用户明确安装/信任时工作；UI 提供 CA 安装说明/路径，但不自动修改系统信任库。

### 5.4 插件 manifest 与本地开发包

新增一个独立、可打包目录，例如 `plugin-package/`，仅放运行时必需内容：

```text
plugin-package/
  manifest.json
  plugin_main.py
  addon.py
  database.py
  mcp_server.py
  ui/...
  vendor/                 # 如果依赖体积 spike 通过
  icon.png                # 可选
```

manifest 首版取值建议：

- `id`: 由维护者提供的反向域名 ID（至少三段，确定后不要随意改）。
- `version`: 从 `0.1.0` 开始按插件发布递增。
- `entry`: `plugin_main.py`。
- `runtime`: `python`，版本与依赖安装说明一致；若最终做 self-contained `.exe`，改 `none` 并重新验证 package size。
- `ui.embedded`: `true`。
- `permissions`: `config.read`、`config.write`、`target.launch`、`target.control`；Ghost 服务端把已授予的通用权限映射到通用命令白名单。
- `standalone`: `true`，便于用户不经 Ghost 诊断安装/依赖问题；standalone 模式不能读取 Ghost API。

打包必须从白名单 stage 目录运行 `gpkg.py pack`。不要从 NetTraceMVP 根目录运行：当前根目录包含 `.venv`、`data`、SQLite/WAL、缓存和本地工作文件，打包器不会遵从 `.gitignore`。

## 6. 分阶段实施与验收

当前已编写 Ghost 通用权限/API 授权与 Snagbox MCP 桥接；以下阶段记录后续构建/运行验收工作。

### 阶段 0：接入可行性 spike（先做）

1. 用 Ghost 的最小 Python 模板插件实现握手、动态 loopback UI、停止 event；本地开发者模式安装/启用/停用。
2. 停用插件时确认 `stopEvent` 能触发 MCP、UI 和 mitmproxy 的顺序关闭，并让 addon 完成 SQLite flush。
3. 单独验证 Ghost HTTP CONNECT upstream → mitmproxy regular listener 的 loopback 路径；根证书旁路时确认 TLS 字节进入 `tcp_message`，且普通 HTTP 仍进入 `http`。
4. 在干净插件 stage 目录中安装依赖并测 `.gpkg` 大小；核对 SQLite/`.venv` 未出现在包中。
5. 验证 MCP Streamable HTTP 能否使用系统分配端口并把实际 endpoint 返回 UI。

**验收门槛**：本地插件能在 Ghost 插件页出现运行态和 iframe；停用后进程内服务端口释放；Ghost 上游能完成 TCP CONNECT 测试；包中没有数据库或 `.venv`。任一项不通过，先收敛实现再分发。

### 阶段 1：插件编排骨架

- 新建插件包目录、manifest、pack staging/清理脚本。
- 实现握手校验、一次 stdout 回执、UI loopback server、stop event、服务线程关闭和错误状态。
- 完成 `gpkg.py pack` → Ghost 开发者模式本地安装 → 启用/停用/重启的循环。

**验收**：缺 Python/缺依赖/端口冲突/服务启动失败都有可见故障；正常停用可优雅退出，无残留监听端口。

### 阶段 2：采集服务接入

- 让插件启动 mitmproxy regular mode + addon，并启动 MCP Streamable HTTP。
- 传入动态 endpoint、数据库 `dataDir` 路径与 capture label。
- 增加 readiness 检查，不以“进程 CreateProcess 成功”冒充 listener 已就绪。
- 先完成 TCP、HTTP、DNS 样例；TLS 用明确受信任 CA 的测试客户端验证；UDP 仅记录试验结果。

**验收**：目标样例的流量经 Ghost 上游进入 mitmproxy；SQLite 同 UID 关联预期事件和 TCP chunks；MCP 查询同一数据库；停止服务后最后一个 session 正常结束、WAL/checkpoint 可恢复。

### 阶段 3：嵌入管理 UI 与数据操作

- 做 start/pause/resume、健康状态、endpoint 复制、数据库信息、错误日志入口和配置说明。
- 把服务关闭、暂停采集、清除数据拆成独立操作；清除数据有二次确认。
- 做从旧 `data/nettrace.sqlite` 的可选一致性导入/备份流程。
- 显示卸载将删除插件私有 dataDir，提供导出/备份说明。

**验收**：UI 不访问 Ghost 会话 API；暂停期间 Ghost 上游仍转发但不再落采集行；插件停用只关闭本机代理服务，不删除库。

### 阶段 4：本地包验证与后续发布准备

- 对 stage 构建产物做包清单审计、secret 检查、依赖锁定、size ceiling 检查。
- 通过 Ghost 的开发者模式装本地 `.gpkg`，迭代同版本覆盖、版本升级、禁用、卸载、dataDir 保留/删除行为。
- 先内部使用；只有需要面向其他 Ghost 用户分发时才建开发者签名、发布资产和注册表条目。

**验收**：`.gpkg` 不含数据库、WAL、`.venv`、私钥或机器绝对路径；干净机器按说明可启用；卸载与数据保留策略符合 UI 承诺。

## 7. 风险、边界和先决决策

| 风险/决策 | 影响 | 建议处理 |
|---|---|---|
| 权限类别只存在于改造分支 | 旧 Ghost 会以 `unknown_permission` 拒绝 snagbox 清单 | 使用包含这些通用权限类别的 Ghost 版本 |
| Ghost API 不提供 payload | 单靠插件 API 无法抓包 | mitmproxy 作为独立子服务继续采集 |
| mitmproxy 到 Ghost CONNECT 的 listener 模式未在此工作区实测 | 代理模式选错会无法启动或形成错误链路 | 阶段 0 先做 localhost CONNECT e2e；TCP 优先 |
| 代理端口 8080 被占用 | 上游节点无法连接 | 插件启动握手明确失败；MCP/UI 使用回环动态端口 |
| Python runtime 不安装第三方包 | 初次启用可能缺 mitmproxy/MCP | 先验证 vendor 体积；无自动 pip 安装 |
| `.gpkg` pack 会收整个源树 | `.venv` 和 raw DB 会进入包 | 只对干净白名单 stage 目录 pack；审计包内路径 |
| 本机数据库敏感且卸载删除 `.data` | 凭据、token、协议样本有隐私风险 | 数据导出/备份；卸载提示；loopback 与最小 API |
| 插件停用时本地上游消失 | 依赖该上游的程序连接会失败 | 启用/停用提示，文档说明回退/恢复原上游方式 |
| UDP 端到端链路未知 | 宣称支持会误导用户 | 首版按未支持处理，验证通过再扩展 |
| Snagbox 插件停用后节点仍保存在 Ghost | 目标继续指向已关闭的回环 listener | UI 显示节点与端口；重新启用后会自动修复并恢复 listener |

当前采用的产品选择：插件停用会关闭 loopback listener；依赖由用户预装到 Ghost 选中的 Python；数据库放在插件私有 `dataDir`，卸载前由用户备份。尚待实际构建与 Ghost 主机验证的事项见下方阶段验收。

## 8. 参考实现和依据

- Ghost 插件 SDK 概览：`C:\Users\admin\Desktop\ghost-proxifier-ui-snagbox\docs\plugin-sdk\README.md`
- Manifest/runtime/UI 契约：`...\docs\plugin-sdk\spec-manifest.md`
- 握手与停止 event：`...\docs\plugin-sdk\spec-host-protocol.md`
- 权限及 payload 边界：`...\docs\plugin-sdk\spec-plugin-api.md`
- 插件进程/Job Object：`...\docs\architecture\plugin-center.md` §7
- 官方示例：`...\examples\plugin-template\` 与 `...\examples\plugin-events-viewer\`
- snagbox 启动与功能：本目录 `README.md`、`plugin_main.py`、`addon.py`、`database.py`、`mcp_server.py`；SQLite 字段详见 `DATABASE_SCHEMA.md`
