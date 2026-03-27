# firmware-scan-mcp

MCP server for [firmware-scan-service](../firmware-scan-service). Exposes firmware scan registration, vulnerability management, and diagnostics as MCP tools consumable by Claude Code or any MCP-compatible client.

## Prerequisites

- Python 3.10+
- `firmware-scan-service` running (`docker compose up` in `../firmware-scan-service`)

## Setup

```bash
cd firmware-scan-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Register with Claude Code

```bash
claude mcp add firmware-scan-service \
  /home/eleemhuis/firmware-scan-mcp/.venv/bin/python \
  /home/eleemhuis/firmware-scan-mcp/server.py
```

Or add manually to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "firmware-scan-service": {
      "command": "/home/eleemhuis/firmware-scan-mcp/.venv/bin/python",
      "args": ["/home/eleemhuis/firmware-scan-mcp/server.py"],
      "env": {
        "FIRMWARE_SCAN_API": "http://localhost:8080"
      }
    }
  }
}
```

The `FIRMWARE_SCAN_API` environment variable controls which API instance the server points to. Defaults to `http://localhost:8080`.

## Tools

| Tool | Description |
|---|---|
| `register_scan` | Register a device and firmware version for scanning |
| `list_vulnerabilities` | Return all CVE IDs in the registry, sorted |
| `report_vulnerabilities` | Add one or more CVE IDs to the registry |
| `scan_status_summary` | Count scans per status (scheduled / started / complete / failed) |
| `top_vulnerabilities` | Top N CVEs ranked by detection count |

## Testing

**Interactive UI** — downloads and opens the MCP inspector at `http://localhost:5173` (requires `npm`):

```bash
.venv/bin/mcp dev server.py
```

**Single tool from the command line:**

```bash
.venv/bin/python - <<'EOF'
import asyncio
from mcp.client.stdio import stdio_client
from mcp import ClientSession, StdioServerParameters

async def main():
    params = StdioServerParameters(
        command=".venv/bin/python", args=["server.py"]
    )
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool("list_vulnerabilities", {})
            print(result)

asyncio.run(main())
EOF
```

**Quick smoke test** (calls tool functions directly, no MCP transport):

```bash
.venv/bin/python -c "
import server
print(server.list_vulnerabilities())
print(server.scan_status_summary())
"
```