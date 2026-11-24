# Report Template

Save the report as `security-audit-report.md` in the results folder
(`output_dir` from `export_findings`), then show the user the summary table
and the path to the report.

## Severity rules

- **High:** can be exploited remotely without logging in, or exposes a live
  secret. Examples: SQL/command injection, unsafe deserialization of request
  data, unauthenticated admin action, hard-coded production key, dependency
  with a known remotely exploitable CVE.
- **Medium:** needs another weakness or special conditions to exploit.
  Examples: weak password hashing, debug mode, CORS `*`, sensitive data in
  logs.
- **Low:** defense-in-depth or hygiene. Examples: verbose errors, missing
  security headers.

## Template

```
# Security Audit Report — <project> — <YYYY-MM-DD>

**Scope:** <folders audited>
**Scanned at:** <scanned_at from run_all_scans>
**Method:** Automated scanning (<scanner versions, e.g. gitleaks 8.30.1,
semgrep 1.186.0, osv-scanner 2.7.1>), followed by manual verification of
every scanner finding and manual review for access control and logic flaws,
performed by Claude using the security-audit skill.

## Summary
<n> findings: <x> high, <y> medium, <z> low
Scanner leads reviewed: <total from run_all_scans> → <confirmed> confirmed,
<merged> merged as duplicates, <dropped> false positives.

| # | Finding | Severity | Source | SOC 2 | ISO 27001 |
|---|---|---|---|---|---|
| 1 | <title> | High | semgrep | CC7.1 | A.8.28 |
| 2 | <title> | High | manual review | CC6.1, CC6.3 | A.5.15, A.8.5 |

## Findings

### 1. <title> — Severity: High
- **ID:** AEK-3f9a1c02b7 (from export_findings; matches the ticket)
- **Location:** path/to/file.py:42 (and :45 if merged)
- **Source:** <scanner + rule id, or "manual review">
- **Evidence:** `<offending line, secrets masked>`
- **Why it matters:** <one sentence>
- **Fix:** <corrected code, see fix-examples.md>
- **Controls:**
  - SOC 2 CC7.1: Detects configuration changes and new vulnerabilities
  - ISO 27001 A.8.28: Secure coding

## Dropped leads
Every scanner lead that did not become its own finding, so the totals in the
Summary add up.

| Scanner | Location | Rule | Verdict | Reason |
|---|---|---|---|---|
| semgrep | app.py:24 | sql-injection | Duplicate of #2 | Input source of the same injection |
| semgrep | tests/test_db.py:10 | sql-injection | False positive | Test fixture with a constant string |

(Write "None." if there were none.)

## Limitations
- <scanners that failed or weren't installed, with install command>
- <what was not checked: infrastructure, cloud config, runtime behavior>
```

Never print a full secret value. Show the first 4 characters and mask the rest.
