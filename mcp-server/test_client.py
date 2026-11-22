"""Talk to the MCP server the same way Claude Code does, without Claude.

Run:  .venv/bin/python mcp-server/test_client.py
"""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).parent


async def main() -> None:
    # Start server.py as a subprocess, exactly like Claude Code will.
    params = StdioServerParameters(command=sys.executable, args=[str(HERE / "server.py")])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()  # handshake

            tools = await session.list_tools()  # what Claude sees
            for tool in tools.tools:
                print(f"TOOL {tool.name}: {tool.description.splitlines()[0]}")
                print(f"     input schema: {tool.input_schema['properties']}")

            result = await session.call_tool("hello", {"name": "world"})
            print("\nhello ->", result.content[0].text)

            target = str(HERE.parent / "examples" / "vulnerable-app")
            result = await session.call_tool("scan_secrets", {"path": target})
            print("scan_secrets ->", result.structured_content)


asyncio.run(main())
