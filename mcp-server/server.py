"""audit-evidence-kit MCP server.

Tools:
  - scan_secrets:      hard-coded secrets (gitleaks)
  - scan_code:         code vulnerabilities (semgrep)
  - scan_dependencies: known-vulnerable packages (osv-scanner)
  - run_all_scans:     all three, plus a summary
  - list_endpoints:    every Flask route, for checking authentication

Tools are thin wrappers: the real work lives in scanners.py.
"""

import re
from pathlib import Path
from typing import TypedDict

from mcp.server import MCPServer

import scanners

mcp = MCPServer("audit-evidence-kit")

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}


# Typed return values become an output schema: Claude knows the exact fields
# before it calls the tool. A bare `dict` gives the SDK nothing to describe.
class Finding(TypedDict):
    scanner: str
    rule: str
    issue_type: str
    severity: str
    file: str
    line: int | None
    message: str
    evidence: str


class Summary(TypedDict):
    total: int
    high: int
    medium: int
    low: int


class ScanReport(TypedDict):
    summary: Summary
    findings: list[Finding]
    errors: dict[str, str]


@mcp.tool()
def scan_secrets(path: str) -> list[Finding]:
    """Scan a folder for hard-coded secrets (API keys, tokens, passwords,
    private keys) using gitleaks. Secrets in the results are masked.
    Returns normalized findings."""
    return scanners.run_gitleaks(path)


@mcp.tool()
def scan_code(path: str) -> list[Finding]:
    """Scan a folder's source code for vulnerabilities (injection, weak
    crypto, debug mode, sensitive logging, and more) using semgrep. Works for
    most languages. Returns normalized findings, one per bug per line."""
    return scanners.run_semgrep(path)


@mcp.tool()
def scan_dependencies(path: str) -> list[Finding]:
    """Check a folder's dependency files (requirements.txt, package-lock.json,
    go.mod, ...) for packages with known CVEs using osv-scanner. Returns one
    finding per vulnerable package, with the version that fixes it."""
    return scanners.run_osv(path)


@mcp.tool()
def run_all_scans(path: str) -> ScanReport:
    """Run every scanner (secrets, code, dependencies) on a folder. Use this
    first in a security audit. Returns findings, a summary, and any scanner
    that failed (the others still run). Findings are leads, not verdicts:
    confirm each one by reading the code."""
    findings, errors = [], {}
    for name, run in [("gitleaks", scanners.run_gitleaks),
                      ("semgrep", scanners.run_semgrep),
                      ("osv-scanner", scanners.run_osv)]:
        try:
            findings.extend(run(path))
        except Exception as exc:  # one broken scanner shouldn't stop the audit
            errors[name] = str(exc)

    findings = scanners.dedupe(findings)  # same bug from two scanners -> one finding
    summary = {sev: sum(f["severity"] == sev for f in findings)
               for sev in ("high", "medium", "low")}
    return {"summary": {"total": len(findings), **summary},
            "findings": findings, "errors": errors}


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


# Run over stdio. Never print() to stdout here: it would corrupt the protocol.
if __name__ == "__main__":
    mcp.run()
