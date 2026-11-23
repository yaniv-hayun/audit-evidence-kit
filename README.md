# audit-evidence-kit

A free Claude Code plugin that audits your code for security vulnerabilities
and writes an **evidence report mapped to SOC 2 and ISO 27001:2022 controls**.

It doesn't just ask Claude to "look for bugs". It runs real open-source
scanners, has Claude verify every finding by reading the code, and records
what was confirmed, merged, or dropped, and why.

```
scanners (fast, noisy)          Claude (judgment)                 report
────────────────────────        ─────────────────────────         ──────────────────────────
gitleaks     → secrets          confirm / merge / drop each lead  findings + severity
semgrep      → code bugs   ──►  find what scanners miss:     ──►  SOC 2 + ISO 27001 controls
osv-scanner  → CVEs             missing auth, CORS, logic         fixes with code
                                                                  dropped leads + reasons
```

See a full sample report: [examples/vulnerable-app/security-audit-report.md](examples/vulnerable-app/security-audit-report.md)

## What a finding looks like

```markdown
### 4. Unsafe YAML deserialization in `/import` — Severity: High
- **Location:** examples/vulnerable-app/app.py:52
- **Source:** semgrep, rule `insecure-deserialization`
- **Evidence:** `yaml.load(request.data, Loader=yaml.Loader)`
- **Why it matters:** `yaml.Loader` can construct arbitrary Python objects,
  so a crafted POST body gives unauthenticated remote code execution.
- **Fix:** `yaml.safe_load(request.data)`
- **Controls:**
  - SOC 2 CC7.1: Detects configuration changes and new vulnerabilities
  - ISO 27001 A.8.28: Secure coding
```

## Install

**1. Prerequisites** (macOS; on Linux, install the same tools from their release pages):
```bash
brew install uv gitleaks semgrep osv-scanner
```

**2. Add the plugin** in Claude Code:
```
/plugin marketplace add yaniv-hayun/audit-evidence-kit
/plugin install audit-evidence-kit@audit-evidence-kit
```
Restart Claude Code, then run `/mcp`. You should see `scanners` connected with 5 tools.

## Use

In any project, ask:
```
run a security audit on this project
```
The report is saved as `security-audit-report.md` in the audited folder.

## What it checks

| Issue type | Found by | SOC 2 | ISO 27001:2022 |
|---|---|---|---|
| Hard-coded secret | gitleaks, semgrep | CC6.1 | A.5.17, A.8.24 |
| Injection (SQL, command, `eval`) | semgrep | CC7.1, CC8.1 | A.8.28 |
| Unsafe deserialization | semgrep | CC7.1, CC8.1 | A.8.28 |
| Weak crypto / password hashing | semgrep | CC6.1, CC6.7 | A.8.24 |
| Sensitive data in logs | semgrep | CC6.1, CC7.2 | A.8.11, A.8.15 |
| Insecure defaults / debug mode | semgrep | CC7.1, CC8.1 | A.8.9 |
| Vulnerable dependency | osv-scanner | CC7.1 | A.8.8 |
| Missing authentication / authorization | Claude (manual review) | CC6.1, CC6.3 | A.5.15, A.8.5 |
| CORS allows any origin | Claude (manual review) | CC6.6 | A.8.26 |

The full mapping and control titles are in
[skills/security-audit/references/control-mapping.md](skills/security-audit/references/control-mapping.md).

## Repository layout

```
.claude-plugin/       plugin + marketplace manifests (registers the MCP server)
skills/security-audit/
  SKILL.md            the audit process Claude follows
  references/         control mapping, report template, fix examples
mcp-server/
  server.py           MCP tools (thin wrappers)
  scanners.py         runs the scanners, normalizes their output
  test_client.py      exercises the server without Claude
examples/vulnerable-app/   deliberately vulnerable test target + sample report
```

## Develop

```bash
uv run --directory mcp-server test_client.py   # test the MCP server alone
claude --plugin-dir .                          # run Claude Code with this plugin loaded
claude plugin validate .                       # check the manifests
```

`examples/vulnerable-app` contains planted bugs. After any change, run the
audit on it and check the report still finds all of them.

## Limitations

- This is a tool to **prepare** evidence, not a substitute for an auditor or a
  penetration test. Control mappings are a reasonable starting point; your
  auditor has the final word.
- Static analysis only: no infrastructure, cloud configuration, or runtime
  testing.
- `list_endpoints` currently understands Flask routes only. Other frameworks
  are reviewed by reading the code.

## License

MIT. See [LICENSE](LICENSE).
