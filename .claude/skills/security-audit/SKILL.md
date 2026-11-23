---
name: security-audit
description: Audits a codebase for security vulnerabilities and maps each finding to SOC 2 and ISO 27001:2022 controls. Runs real scanners (gitleaks, semgrep, osv-scanner), confirms each finding by reading the code, and writes an evidence report. Use when the user asks for a security audit, security review, vulnerability scan, or SOC 2 / ISO 27001 compliance check of code.
allowed-tools: Read, Grep, Glob, Write, mcp__audit-evidence-kit__run_all_scans, mcp__audit-evidence-kit__list_endpoints
---

# Security Audit

You are performing a security audit of the user's code. Your output is a
report a compliance auditor could rely on as evidence.

Scanners and you do different jobs:
- **Scanners** are fast and thorough but noisy. Their findings are *leads*.
- **You** decide which leads are real, merge duplicates, and find the bugs
  scanners can't see (logic and access-control flaws).

## Steps

### 1. Scope
Ask which folder to audit if it isn't clear. Otherwise use the current project.
Use the absolute path when calling tools.

### 2. Run the scanners
Call `run_all_scans` from the `audit-evidence-kit` MCP server with the folder.
Keep `scanned_at` and `scanners` (tool versions) for the report.

- If `errors` lists a scanner, continue with the others and record the gap
  in the report's **Limitations** section, with the install command.
- If the MCP server isn't available at all, tell the user, then do the whole
  audit by manual review (step 4) and state "manual review only" in the
  report's **Method**.

### 3. Triage every scanner finding
For each finding, read the code around the reported line (at least 10 lines
of context) and give it one verdict:

| Verdict | When | What to do |
|---|---|---|
| **Confirmed** | The bug is real and the code is reachable | Keep it |
| **Duplicate** | Same root cause as another finding (e.g. the line where input enters and the line where it reaches the SQL query) | Merge into one finding; list all locations. List it under **Dropped leads** with verdict "Duplicate of #n" |
| **False positive** | Not exploitable: test file, constant input, already sanitized, dead code | Drop it, and list it under **Dropped leads** with verdict "False positive" and a one-line reason |

The scanner's severity is a hint. Assign the final severity yourself using
the rules in `references/report-template.md`.

For dependency findings: a vulnerable package that is declared in a
dependency file is **always Confirmed**, because it gets installed wherever
the project is deployed. Reachability changes the *severity*, not the
verdict: if the package is never imported (directly or by an imported
package), lower the severity one level and say so in **Why it matters**.
Keep the CVE list and the fixed version from the scanner.

### 4. Manual review: what scanners miss
Scanners can't judge intent. Check these yourself:

- **Missing authentication / authorization.** Call `list_endpoints`. For each
  endpoint decide whether it *should* require login. Public by design (login,
  register, health check, public pages) is not a finding. Anything that reads
  user data or changes data is. Admin actions also need a role check.
- **CORS** allowing any origin (`*`, or `CORS(app)` with no `origins`).
- **Insecure configuration** the scanners didn't flag (cookies without
  `Secure`/`HttpOnly`, missing CSRF protection on state-changing forms).
- **Business logic** flaws visible in the code (e.g. a user can change
  another user's data by changing an ID).

Mark these findings with source **manual review**.

### 5. Map to controls
Read `references/control-mapping.md` and tag each finding with its SOC 2 and
ISO 27001 controls, using the official titles listed there.

### 6. Write the report
Read `references/report-template.md` and follow it exactly. For each **Fix**
line, read `references/fix-examples.md` and show corrected code in its style.

Never print a full secret value, even if you see it while reading code.
