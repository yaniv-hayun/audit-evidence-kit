"""audit-evidence-kit MCP server.

Lesson 3: two tools.
  - hello:        the smallest possible tool, to prove the wiring works
  - scan_secrets: a tiny regex secret scanner (replaced by gitleaks in Lesson 4)
"""

import re
from pathlib import Path

from mcp.server import MCPServer

# 1. Create the server. The name is what Claude Code shows in /mcp.
mcp = MCPServer("audit-evidence-kit")


# 2. A tool is a normal Python function with a decorator.
#    - The function name becomes the tool name.
#    - The type hints become the input schema Claude sees.
#    - The docstring becomes the tool description. Claude reads it to decide
#      WHEN to call the tool, so write it like the skill's `description`.
@mcp.tool()
def hello(name: str) -> str:
    """Say hello. Use only to test that the audit-evidence-kit server works."""
    return f"Hello {name}, the audit-evidence-kit MCP server is running."


SECRET_PATTERNS = {
    "stripe-live-key": re.compile(r"sk_live_[0-9A-Za-z]{10,}"),
    "aws-access-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github-token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "generic-password": re.compile(r"""(?i)(password|passwd|secret)\s*=\s*["'][^"']{4,}["']"""),
}
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}


def mask(value: str) -> str:
    """Keep the first 4 characters, hide the rest. Never return a full secret."""
    return value[:4] + "*" * max(len(value) - 4, 4)


@mcp.tool()
def scan_secrets(path: str) -> list[dict]:
    """Scan a folder for hard-coded secrets (API keys, tokens, private keys,
    passwords). Returns one item per finding with file, line, rule and a
    masked match. Use during a security audit before reading code manually.
    """
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise ValueError(f"Path not found: {root}")

    files = [root] if root.is_file() else [
        p for p in root.rglob("*")
        if p.is_file() and not SKIP_DIRS & set(p.parts)
    ]

    findings = []
    for file in files:
        try:
            lines = file.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for rule, pattern in SECRET_PATTERNS.items():
                if match := pattern.search(line):
                    findings.append({
                        "file": str(file.relative_to(root.parent if root.is_file() else root)),
                        "line": line_no,
                        "rule": rule,
                        "match": mask(match.group(0)),
                    })
    return findings


ROUTE_RE = re.compile(r"""@\w+\.route\(\s*["']([^"']+)["'](?:.*?methods\s*=\s*\[([^\]]*)\])?""")


@mcp.tool()
def list_endpoints(path: str) -> list[dict]:
    """List every Flask HTTP endpoint (@app.route) in a folder, with file,
    line, route and HTTP methods. Use during a security audit to check each
    endpoint for missing authentication or input validation.
    """
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise ValueError(f"Path not found: {root}")

    endpoints = []
    for file in root.rglob("*.py"):
        if SKIP_DIRS & set(file.parts):
            continue
        lines = file.read_text(errors="ignore").splitlines()
        for line_no, line in enumerate(lines, start=1):
            if match := ROUTE_RE.search(line):
                methods = re.findall(r"[A-Z]+", match.group(2) or "") or ["GET"]
                endpoints.append({
                    "file": str(file.relative_to(root)),
                    "line": line_no,
                    "route": match.group(1),
                    "methods": methods,
                })
    return endpoints

# 3. Run over stdio: Claude Code starts this script as a subprocess and talks
#    to it through stdin/stdout. That's why you must never print() to stdout
#    in an MCP server: it would corrupt the protocol messages.
if __name__ == "__main__":
    mcp.run()
