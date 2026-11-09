import sys
import time
import json
import sqlite3
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from database import NetTraceDB, readonly_connection
from addon import FilterManager, FilterInstance
import mcp_server

TEST_DB = Path("./data/test_phase1.sqlite").resolve()
if TEST_DB.exists():
    TEST_DB.unlink()

print("== 1. 初始化测试数据库 ==")
db = NetTraceDB(TEST_DB)
db.close()
print("数据库初始化成功，包含 filter_registry 和 filter_hits 表")

print("\n== 2. 测试 mcp_server: install_filter (语法与安全检查) ==")
mcp_server._db_path = TEST_DB

# 测试安装不安全代码 (应该被拦截)
unsafe_res = mcp_server.install_filter(
    "unsafe_hack",
    "import os\ndef on_request(flow):\n    os.system('whoami')"
)
print("不安全模块拦截测试:", unsafe_res)
assert unsafe_res.get("error") == "disallowed_module"

# 测试语法错误
syntax_res = mcp_server.install_filter("syntax_err", "def on_request(flow):\n  if")
print("语法错误拦截测试:", syntax_res)
assert syntax_res.get("error") == "syntax_error"

# 测试正常安装一个 Mock Filter
mock_code = """
def on_request(flow):
    if "/api/mock_test" in flow.request.path:
        flow.response = http.Response.make(
            200,
            json.dumps({"status": "success", "data": "mocked_by_ai"}).encode("utf-8"),
            {"Content-Type": "application/json"}
        )
"""
install_res = mcp_server.install_filter(
    "mock_rule", mock_code, description="拦截特定测试端点并返回预设 Mock 数据", priority=10
)
print("正常 Mock Filter 安装结果:", install_res)
assert install_res.get("status") == "ok"
assert install_res.get("description") == "拦截特定测试端点并返回预设 Mock 数据"

# 测试正常安装一个使用预注入库 (hmac, hashlib, base64) 的 Rewrite Filter
rewrite_code = """
def on_request(flow):
    if "/api/v1/user" in flow.request.path:
        # 使用预注入的 hmac, hashlib 和 base64 免 import 直接计算签名
        raw_msg = flow.request.path.encode("utf-8")
        sig = hmac.new(b"secret_key", raw_msg, hashlib.sha256).digest()
        flow.request.headers["X-Custom-Sign"] = base64.b64encode(sig).decode("utf-8")
        flow.request.query["injected_param"] = "test_val"
"""
install_res2 = mcp_server.install_filter(
    "rewrite_sign", rewrite_code, description="自动计算 HMAC-SHA256 签名并注入请求头", priority=20
)
print("正常 Rewrite Filter 安装结果 (使用预注入模块):", install_res2)
assert install_res2.get("status") == "ok"
assert install_res2.get("description") == "自动计算 HMAC-SHA256 签名并注入请求头"

print("\n== 3. 测试 FilterManager 动态热加载与拦截执行 ==")
fm = FilterManager(TEST_DB)
fm.sync_from_db()
print(f"FilterManager 成功加载 filters: {list(fm.filters.keys())}")
assert len(fm.filters) == 2

class MockHeaders(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    def items(self, multi=False):
        return super().items()

class MockRequest:
    def __init__(self, url):
        self.url = url
        self.path = url.split("://")[-1].split("/", 1)[-1]
        self.path = "/" + self.path
        self.headers = MockHeaders({"User-Agent": "TestClient/1.0"})
        self.query = {}
        self.raw_content = b'{"name": "original"}'

class MockFlow:
    def __init__(self, url):
        self.request = MockRequest(url)
        self.response = None
        self.error = None
        self.tags = set()

class MockAsyncDB:
    def __init__(self):
        self.hits = []
    def add_filter_hit(self, row):
        self.hits.append(row)
        # 实际写回数据库以供查询
        conn = sqlite3.connect(TEST_DB)
        cols = list(row.keys())
        values = list(row.values())
        placeholders = ",".join("?" for _ in cols)
        conn.execute(f"INSERT INTO filter_hits ({','.join(cols)}) VALUES ({placeholders})", values)
        conn.commit()
        conn.close()

mock_db = MockAsyncDB()

# 3.1 模拟触发 Mock
flow_mock = MockFlow("https://api.example.com/api/mock_test")
fm.handle_request(flow_mock, "NT_UID_001", mock_db)
print("Mock 执行后 flow.response 状态码:", flow_mock.response.status_code if flow_mock.response else None)
assert flow_mock.response is not None
assert flow_mock.response.status_code == 200

# 3.2 模拟触发 Rewrite
flow_rewrite = MockFlow("https://api.example.com/api/v1/user/info")
fm.handle_request(flow_rewrite, "NT_UID_002", mock_db)
print("Rewrite 执行后 headers:", dict(flow_rewrite.request.headers))
assert "X-Custom-Sign" in flow_rewrite.request.headers
assert len(flow_rewrite.request.headers["X-Custom-Sign"]) > 10

time.sleep(0.5)

print("\n== 4. 测试可观测性：查询 filter_hits 命中记录 ==")
conn = readonly_connection(TEST_DB)
hits = conn.execute("SELECT id, flow_uid, filter_name, action, target_url, diff_summary, status FROM filter_hits ORDER BY id").fetchall()
conn.close()
for h in hits:
    print(f"命中记录 #{h['id']}: filter={h['filter_name']}, action={h['action']}, uid={h['flow_uid']}, diff={h['diff_summary']}")
assert len(hits) == 2

# 4.1 测试 mcp_server 提供的专属便捷读取工具: get_filter_hits
mcp_hits = mcp_server.get_filter_hits(action="MOCK")
print("get_filter_hits(action='MOCK') 结果:", mcp_hits)
assert mcp_hits["count"] == 1
assert mcp_hits["hits"][0]["filter_name"] == "mock_rule"
assert mcp_hits["hits"][0]["diff"]["mocked_status"] == 200

print("\n== 5. 测试 mcp_server: list_filters (统计聚合指标) ==")
list_res = mcp_server.list_filters()
print("list_filters 结果:", json.dumps(list_res, indent=2, ensure_ascii=False))
assert list_res["total"] == 2
# 验证 mock_rule 命中数为 1
mock_item = next(f for f in list_res["filters"] if f["name"] == "mock_rule")
assert mock_item["total_hits"] >= 1
assert mock_item["description"] == "拦截特定测试端点并返回预设 Mock 数据"

print("\n== 6. 测试熔断保护 (Circuit Breaker) ==")
broken_code = """
def on_request(flow):
    raise ZeroDivisionError("Simulated dynamic crash")
"""
mcp_server.install_filter("buggy_rule", broken_code, priority=1)
fm.sync_from_db()
flow_err = MockFlow("https://api.example.com/test_error")
# 连续调用 3 次触发熔断
for _ in range(3):
    fm.handle_request(flow_err, "NT_UID_ERR", mock_db)

assert fm.filters["buggy_rule"].is_tripped is True
print("Buggy filter 熔断验证成功: is_tripped = True")

print("\n=======================================================")
print("阶段 1（Phase 1）所有单元测试与集成测试 100% 验证通过！")
print("=======================================================")
