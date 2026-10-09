# snagbox

A local, process-routed traffic capture experiment: Ghost Proxifier directs a target application's TCP flow through mitmproxy; a Python addon stores Zeek-shaped events and raw transport chunks in SQLite; an MCP server lets an AI inspect the schema and query the database.


## Requirements

- Python 3.12 or newer recommended
- Ghost Proxifier for process-specific TCP routing (optional; any HTTP CONNECT client can be used for a smoke test)
- mitmproxy and the Python MCP SDK (installed below)

## Install

From this folder in PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Start capture

For normal use, install and enable the Ghost plugin described below. It starts
mitmproxy and MCP in the plugin process and registers the dedicated `snagbox`
upstream automatically. The old two-window `start_snagbox.bat` workflow has
been removed. The commands below remain available for manual development.

The proxy and MCP can also be started separately from a terminal. Start a regular HTTP proxy with the addon loaded:

```powershell
mitmdump --mode regular --listen-host 127.0.0.1 --listen-port 8080 `
  --set nettrace_db=./data/nettrace.sqlite `
  --set nettrace_label=target-app `
  -s .\addon.py
```

Configure a Ghost HTTP upstream node to `127.0.0.1:8080`, then route one target process through that node. A simple non-Ghost smoke test can set an HTTP proxy to `http://127.0.0.1:8080`.

The addon enqueues records to a background SQLite writer so its mitmproxy hooks do not wait for database I/O. The queue is bounded (8192 records / 64 MiB); if the database cannot keep up, new capture records are dropped to protect proxy responsiveness, and the drop count is reported at shutdown. A single oversized HTTP body is allowed to drain when the queue is otherwise empty; while it is being written, further events may be dropped to keep queued body data bounded. The addon writes to `data/nettrace.sqlite`. Generic TCP records are proxy-level chunks; their boundaries are not application-message boundaries. HTTP request and response headers are stored as ordered name/value pairs (including repeated fields), and request/response entity bytes are stored in `http.request_body` and `http.response_body` BLOB columns. With no trusted Snagbox CA, HTTPS stays encrypted and its tunnel bytes are recorded in `tcp_message` with a matching `conn` row; ordinary HTTP remains parsed into `http`. With a trusted CA, successfully intercepted HTTPS is stored as HTTP metadata and body data instead. Headers and bodies can contain credentials, cookies, or other sensitive content, so protect the database accordingly.

## Ghost Proxifier plugin

The Ghost manifest and whitelist pack builder live in `plugin-package/`; the
plugin entry is `plugin_main.py` in the project root. Run
`plugin-package/build_plugin.ps1 -GhostRepo <path-to-ghost-proxifier-ui-snagbox>`
to build a clean `.gpkg` from a whitelist staging directory. The package does
not include `.venv`, `data/`, SQLite files, or local secrets. Ghost's Python
runtime does not install project dependencies; install `mitmproxy`, the MCP
Python SDK, Uvicorn, and Matplotlib into the Python interpreter selected by
Ghost before enabling the plugin.

When enabled, the plugin starts a local mitmproxy HTTP proxy listener on
`127.0.0.1:8080`, starts MCP Streamable HTTP on a loopback port, and uses
Ghost's generic configuration APIs to create or correct one HTTP upstream
named `snagbox`. It reads the config, deduplicates by name, and saves it back;
Ghost preserves masked credentials for other nodes. The node is not globally activated. In the MCP client, use
The process-control MCP actions are `list_snagbox_processes`,
`start_snagbox_program` and `stop_snagbox_program`. The Agent resolves the
requested program's main executable and passes its absolute path as
`target_path`. Start first reads Ghost's process groups and matches the
executable path on the `snagbox` upstream, including stopped groups. If a
matching group is already running, it returns that group without starting a
duplicate. If the group exists but is stopped, it launches that saved group;
only when no matching group exists does it call Ghost's injection API to create
one. Listing and stopping use the generic process-statistics and process-tree
APIs, filtering groups by the selected node ID before stopping matching PIDs.

The plugin requests `config.read`, `config.write`, `target.launch` and
`target.control`. Ghost shows each permission's impact in the enable dialog;
the user grants the requested set there. These are general Ghost capability
categories, not snagbox-specific grants. Configuration write is broad enough
to submit the full config, and program control can start or stop processes, so
review those prompts before granting them. Plugin data is stored in Ghost's
private plugin data directory.

`start_snagbox_program` sets the target's saved DNS mode to `dot` both for new
injections and reused target groups. Configure an optional chained HTTP proxy
through MCP with `set_upstream_http_proxy(proxy_url, username, password)`;
for example, use `http://127.0.0.1:3128` and provide credentials only when the
proxy requires HTTP Basic authentication. Call `get_upstream_http_proxy` to
check whether it is enabled (the password is never returned). Pass an empty
`proxy_url` to clear the chain. The route is Ghost target → Snagbox on
`127.0.0.1:8080` → optional HTTP proxy. Changes apply to new connections;
existing application connections may need to reconnect. The setting is saved
in Snagbox's private data directory as `upstream_http_proxy.json`.

## Start the MCP server

For manual development, start the MCP server with Streamable HTTP transport in a separate terminal:

```powershell
python .\mcp_server.py --db .\data\nettrace.sqlite --transport streamable-http --host 127.0.0.1 --port 8000
```

The endpoint is `http://127.0.0.1:8000/mcp`. Or use stdio transport with an MCP client in a second terminal:

```powershell
python .\mcp_server.py --db .\data\nettrace.sqlite
```

The server uses MCP stdio transport. Add it to your AI client's MCP configuration. Example command and arguments:

```json
{
  "command": "C:\\Users\\admin\\Desktop\\NetTraceMVP\\.venv\\Scripts\\python.exe",
  "args": [
    "C:\\Users\\admin\\Desktop\\NetTraceMVP\\mcp_server.py",
    "--db",
    "C:\\Users\\admin\\Desktop\\NetTraceMVP\\data\\nettrace.sqlite"
  ]
}
```

## MCP tools

SQLite 表、字段和索引见 [DATABASE_SCHEMA.md](C:/Users/admin/Desktop/NetTraceMVP/DATABASE_SCHEMA.md)；跨表关联依据、关联强度和已知限制见 [DATA_RELATIONSHIPS.md](C:/Users/admin/Desktop/NetTraceMVP/DATA_RELATIONSHIPS.md)。

- `list_event_tables`: table names, descriptions, and row counts.
- `get_data_relationships`: relationship facts, confidence levels, caveats, and SQL examples. Call it before joining event tables.
- `describe_event_table(table_name)`: field names, SQLite types, nullability, and primary-key flags.
- `query_events_sql(sql, row_limit=100)`: one read-only SELECT/WITH query; response rows are capped at 500 and response size is bounded.
- `render_chart(chart_type, title, data, ...)`: render Agent-selected query-result rows as a PNG. Supports `line`, `bar`, `stacked_bar`, `scatter`, and `histogram`; the Agent chooses the analysis and chart, this tool only renders it.
- `start_listening`: begin writing captured traffic to SQLite.
- `suspend_listening`: temporarily stop recording while the proxy continues forwarding.
- `resume_listening`: resume recording.
- `stop_listening`: stop recording new events and clear existing captured event rows. Snagbox, MCP and proxy forwarding keep running; this is not service shutdown.
- `get_upstream_http_proxy`: show whether an upstream HTTP proxy is configured; credentials are omitted.
- `set_upstream_http_proxy(proxy_url, username="", password="")`: configure or clear Snagbox's chained upstream HTTP proxy. Use `http://host:port`; omit credentials if the proxy does not require Basic authentication.
- `get_https_inspection_status`: report whether Snagbox's root CA is trusted and synchronize HTTPS interception with that state.
- `install_https_root_certificate`: install Snagbox's CA in the current Windows user's Root store and enable HTTPS inspection.
- `uninstall_https_root_certificate`: remove only Snagbox's CA and switch HTTPS to CONNECT passthrough, avoiding untrusted interception certificates. Existing connections may need to reconnect.

Example query (Zeek dotted fields require SQL double quotes):

```sql
SELECT uid, "id.resp_h", "id.resp_p", orig_bytes, resp_bytes
FROM conn
ORDER BY ts DESC
LIMIT 20;
```

Raw TCP data can be inspected without returning large BLOBs:

```sql
SELECT uid, message_index, from_client, content_len, hex(substr(content, 1, 64)) AS first_bytes
FROM tcp_message
ORDER BY message_id DESC
LIMIT 20;
```

`query_events_sql` returns a bounded hex preview when a BLOB column is selected directly. For a known text body, select `CAST(request_body AS TEXT)`; for binary analysis, use bounded slices such as `hex(substr(response_body, 1, 256))`.

## UDP note

The addon implements mitmproxy's UDP flow hooks. End-to-end UDP forwarding from a Ghost SOCKS5 upstream still needs validation: Ghost uses SOCKS5 UDP ASSOCIATE, while mitmproxy's common SOCKS5/regular listener path is not automatically equivalent to its UDP-capable modes. For the first run, verify TCP first; UDP is recorded whenever a supported mitmproxy mode delivers UDPFlow events to the addon.

## Data and privacy

The database can contain raw application traffic, credentials, tokens, and personal content. Keep the database local and delete it when no longer needed. Do not share a capture unless you have reviewed it.

This is an MVP. It does not infer unknown protocol schemas, bypass pinning, decrypt application-level encryption, or replay/modify traffic.
