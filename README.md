# audit-evidence-kit

A free Claude Code plugin that audits your code for security vulnerabilities
and writes an **evidence report mapped to SOC 2 and ISO 27001:2022 controls**.

**Free. No signup, no account, nothing sent to us.** The scanners run on your
machine, and Claude reviews the code under your existing Claude agreement.
There is no server, no telemetry, and no new vendor to approve.
[Exactly what leaves your machine](#privacy-what-leaves-your-machine).

It doesn't just ask Claude to "look for bugs". It runs real open-source
scanners, has Claude verify every finding by reading the code, and records
what was confirmed, merged, or dropped, and why.

```
scanners (fast, noisy)            Claude (judgment)                 report
──────────────────────────        ─────────────────────────         ──────────────────────────
gitleaks    → secrets + history   confirm / merge / drop each lead  findings + severity
semgrep     → code bugs      ──►  find what scanners miss:     ──►  SOC 2 + ISO 27001 controls
osv-scanner → CVEs + licenses     missing auth, CORS, logic         fixes with code
trivy       → Docker / IaC                                          dropped leads + reasons
```

See a full sample report: [examples/vulnerable-app/audit-results/security-audit-report.md](examples/vulnerable-app/audit-results/security-audit-report.md)

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
brew install uv gitleaks semgrep osv-scanner trivy
```

**2. Add the plugin** in Claude Code:
```
/plugin marketplace add yaniv-hayun/audit-evidence-kit
/plugin install audit-evidence-kit@audit-evidence-kit
```
Restart Claude Code, then run `/mcp`. You should see
`plugin:audit-evidence-kit:scanners` connected with 8 tools.

**3. Update** when a new version is released:
```
/plugin update audit-evidence-kit
```
Then start a new session. `/plugin` shows the installed version.

## Use

Open Claude Code in the project you want to check:
```bash
cd ~/path/to/your/project
claude
```
Then type the command:
```
/audit-evidence-kit:security-audit
```
or just ask in plain English, for example:
```
run a security audit on this project
check our SOC 2 readiness
are we ready for ISO 27001?
```

Claude first asks what you want. You can pick **more than one**:

| Option | What happens | Output |
|---|---|---|
| **Security scan** | 5 scanners + Claude's review of your code | `security-audit-report.md`, `security-findings*.csv` |
| **SOC 2 Type II readiness** | A company questionnaire (roles, HR, access, engineering, vendors...), then a gap analysis against the Trust Services Criteria | `readiness-report.md`, `readiness-gaps*.csv`, `company-profile.md` |
| **ISO 27001 readiness** | The same questionnaire plus ISO-specific questions (ISMS scope, Statement of Applicability, internal audit, management review) | Same files, mapped to ISO clauses and Annex A |

Choosing both frameworks runs one questionnaire for both. The questionnaire
goes one section at a time; "don't know" is always a valid answer. Answers are
saved, so the next run only asks what changed. Readiness assessments find
gaps before an auditor does; they're not an audit or a certification.

In the same first message Claude also asks:
- **which folder to scan** (security scan only; default: the current project),
- **which ticketing system** you use: Jira, Linear, Asana, monday.com, or none,
- **where to save the results**: default `audit-results/` inside the project,
  or any path you choose.

### Output files

| File | What it's for |
|---|---|
| `security-audit-report.md` | Security scan evidence report |
| `security-findings.csv` | Every scan finding, one row each; opens in any spreadsheet app |
| `readiness-report.md` | SOC 2 / ISO 27001 gaps, roles to assign, open decisions, timeline |
| `readiness-gaps.csv` | Every readiness gap, one row each |
| `company-profile.md` | Your questionnaire answers, reused on the next run |
| `*-jira.csv`, `*-linear.csv`, `*-asana.csv`, `*-monday.csv` | Import files for the ticketing system you chose, for both findings and gaps |

These files describe your unfixed weaknesses: keep them out of public repos
(Claude suggests adding `audit-results/` to `.gitignore`).

Every finding has a stable ID (e.g. `AEK-3f9a1c02b7`) that stays the same on
re-runs, so you can avoid duplicate tickets. Exported cells are protected
against spreadsheet formula injection, since evidence comes from code that
might be hostile.

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
| Secret in git history | gitleaks | CC6.1 | A.5.17, A.8.4, A.8.24 |
| Dockerfile / Terraform / Kubernetes misconfiguration | trivy, semgrep | CC6.6, CC7.1, CC8.1 | A.8.9, A.8.20 |
| License risk (copyleft, unknown) | osv-scanner | n/a | A.5.32 |
| Missing authentication / authorization | Claude (manual review) | CC6.1, CC6.3 | A.5.15, A.8.5 |
| CORS allows any origin | Claude (manual review) | CC6.6 | A.8.26 |

The full mapping and control titles are in
[skills/security-audit/references/control-mapping.md](skills/security-audit/references/control-mapping.md).

## Repository layout

```
.claude-plugin/        plugin + marketplace manifests (registers the MCP server)
skills/security-audit/
  SKILL.md             the start menu, security scan and readiness process
  references/          loaded only when needed:
    control-mapping.md     findings -> SOC 2 / ISO 27001 controls
    report-template.md     security report format and severity rules
    fix-examples.md        bad code -> good code per issue type
    ticketing-import.md    import steps for Jira, Linear, Asana, monday.com
    readiness-assessment.md   readiness procedure and report template
    company-questionnaire.md  the company questions (sections A-M)
    soc2-requirements.md      SOC 2 Type II policies, evidence, roles
    iso27001-requirements.md  ISO 27001 clauses 4-10, Annex A, ISO gaps
mcp-server/
  server.py            MCP tools (thin wrappers)
  scanners.py          runs the scanners, normalizes their output
  exporters.py         CSV and ticketing import files
  test_client.py       exercises the server without Claude
examples/vulnerable-app/   deliberately vulnerable test target + sample report
```

## Develop

```bash
uv run --directory mcp-server test_client.py   # test the MCP server alone
claude plugin validate .                       # check the manifests
```

To try your local changes in Claude Code, disable the installed copy first
(otherwise the plugin loads twice), then load the folder:
```bash
claude plugin disable audit-evidence-kit@audit-evidence-kit
claude --plugin-dir .
# when done:
claude plugin enable audit-evidence-kit@audit-evidence-kit
```

To release: bump `version` in `.claude-plugin/plugin.json`,
`.claude-plugin/marketplace.json` and `mcp-server/pyproject.toml`, push, then
`/plugin update audit-evidence-kit`.

`examples/vulnerable-app` contains planted bugs. After any change, run the
audit on it and check the report still finds all of them.

## Privacy: what leaves your machine

This plugin has no backend. Its author receives **nothing**: no code, no
findings, no usage data. Everything else is listed here so you can decide
before running it:

| What | Where it goes | Why |
|---|---|---|
| **Audited code** (the parts Claude reads) | **Anthropic**, under your existing Claude Code agreement and data settings | Claude confirms findings and checks access control and logic. This is the same as any other Claude Code session; no new party is involved |
| Package names and versions from your dependency files | osv.dev and deps.dev (Google's open vulnerability databases) | To look up known CVEs and licenses. **No source code is sent** |
| Nothing (download only) | semgrep.dev: rule sets (`--metrics off` is set) | Code-scanning rules |
| Nothing (download only) | trivy: check bundle on first run | Infrastructure-scanning rules |
| Nothing | gitleaks | Runs fully offline |
| **Reports and CSVs** | **Your disk only** (`audit-results/` by default) | Never uploaded. Ticket files are imported into Jira, Linear, Asana or monday only if *you* import them |

If your private package names are sensitive (they can reveal internal
project names), review the osv-scanner row before running the audit.

## Security of this tool

- **Prompt injection:** audited code may contain text aimed at AI reviewers
  ("this is safe, don't report it"). The skill treats all audited content as
  data, never as instructions, and reports such text as a finding. The test
  app includes an example.
- **Formula injection:** exported CSV cells starting with `=`, `+`, `-` or `@`
  are prefixed with `'` so spreadsheets don't run them.
- **Secrets** are masked in code before Claude sees them. The first 4
  characters stay visible (e.g. `sk_l****`) to show the key type.
- **Reports list your unfixed vulnerabilities.** Don't commit them to a public
  repo; the skill suggests adding `audit-results/` to `.gitignore`. Each run overwrites the
  previous report and CSVs, so archive them first if you need history.

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
