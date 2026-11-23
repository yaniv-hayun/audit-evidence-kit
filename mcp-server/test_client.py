"""Talk to the MCP server the same way Claude Code does, without Claude.

Run:  uv run --directory mcp-server test_client.py
"""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).parent
TARGET = str(HERE.parent / "examples" / "vulnerable-app")


async def main() -> None:
    params = StdioServerParameters(command=sys.executable, args=[str(HERE / "server.py")])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("TOOLS:", ", ".join(t.name for t in tools.tools))

            result = await session.call_tool("run_all_scans", {"path": TARGET})
            if result.is_error:
                print("ERROR:", result.content[0].text)
                return
            data = result.structured_content
            print("\nSUMMARY:", data["summary"])
            print("ERRORS: ", data["errors"] or "none")
            for f in data["findings"]:
                where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
                print(f"  [{f['severity']:6}] {f['issue_type']:22} {where:16} {f['scanner']:11} {f['evidence'][:50]}")

            result = await session.call_tool("list_endpoints", {"path": TARGET})
            print("\nENDPOINTS:")
            for e in result.structured_content["result"]:
                print(f"  {e['methods']} {e['route']}  ({e['file']}:{e['line']})")


asyncio.run(main())
