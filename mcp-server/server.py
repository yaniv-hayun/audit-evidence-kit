"""audit-evidence-kit MCP server.

Tools:
  - scan_secrets:        hard-coded secrets in current files (gitleaks)
  - scan_git_history:    secrets in past commits (gitleaks)
  - scan_code:           code vulnerabilities (semgrep)
  - scan_dependencies:   vulnerable packages + license risks (osv-scanner)
  - scan_infrastructure: Dockerfile / Terraform / Kubernetes misconfig (trivy)
  - run_all_scans:       all of the above, plus a summary
  - list_endpoints:      every Flask route, for checking authentication

Tools are thin wrappers: the real work lives in scanners.py.
"""

import re
from datetime import datetime, timezone
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
    scanned_at: str
    scanners: dict[str, str]
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
def scan_git_history(path: str) -> list[Finding]:
    """Scan the git history of a folder for secrets that were committed in
    the past, even if they were later deleted. Secrets are masked. Returns
    one finding per secret, listing the commits that contain it."""
    return scanners.run_gitleaks_history(path)


@mcp.tool()
def scan_dependencies(path: str) -> list[Finding]:
    """Check a folder's dependency files (requirements.txt, package-lock.json,
    go.mod, ...) using osv-scanner for (1) packages with known CVEs, with the
    version that fixes them, and (2) license risks: copyleft or unknown
    licenses."""
    return scanners.run_osv(path)


@mcp.tool()
def scan_infrastructure(path: str) -> list[Finding]:
    """Scan infrastructure-as-code and container files (Dockerfile,
    Terraform, Kubernetes, CloudFormation, Helm) for misconfigurations such
    as containers running as root, public storage buckets, or open firewall
    rules, using trivy."""
    return scanners.run_trivy_config(path)


@mcp.tool()
def run_all_scans(path: str) -> ScanReport:
    """Run every scanner on a folder: secrets (current files and git history),
    code, dependencies and licenses, and infrastructure config. Use this first
    in a security audit. Returns findings, a summary, and any scanner that
    failed (the others still run). Findings are leads, not verdicts: confirm
    each one by reading the code."""
    findings, errors = [], {}
    for name, run in [("gitleaks", scanners.run_gitleaks),
                      ("gitleaks-history", scanners.run_gitleaks_history),
                      ("semgrep", scanners.run_semgrep),
                      ("osv-scanner", scanners.run_osv),
                      ("trivy", scanners.run_trivy_config)]:
        try:
            findings.extend(run(path))
        except Exception as exc:  # one broken scanner shouldn't stop the audit
            errors[name] = str(exc)

    findings = scanners.dedupe(findings)  # same bug from two scanners -> one finding
    summary = {sev: sum(f["severity"] == sev for f in findings)
               for sev in ("high", "medium", "low")}
    return {"scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scanners": scanners.scanner_versions(),
            "summary": {"total": len(findings), **summary},
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
