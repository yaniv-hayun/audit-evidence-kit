# Report Template

Save the report as `security-audit-report.md` in the audited folder, then show
the summary to the user.

## Severity rules

- **High:** can be exploited remotely without logging in, or exposes a live
  secret. Examples: SQL/command injection, unauthenticated admin action,
  hard-coded production key.
- **Medium:** needs another weakness or special conditions to exploit.
  Examples: weak password hashing, debug mode, CORS `*`.
- **Low:** defense-in-depth or hygiene. Examples: verbose errors, missing
  security headers.

## Template

```
# Security Audit Report — <project> — <YYYY-MM-DD>

**Scope:** <folders audited>
**Method:** Manual code review by Claude using the security-audit skill.

## Summary
<n> findings: <x> high, <y> medium, <z> low

| # | Finding | Severity | SOC 2 | ISO 27001 |
|---|---|---|---|---|
| 1 | <title> | High | CC6.1 | A.8.24 |

## Findings

### 1. <title> — Severity: High
- **Location:** path/to/file.py:42
- **Evidence:** `<offending line, secrets masked>`
- **Why it matters:** <one sentence>
- **Fix:** <concrete change>
- **Controls:**
  - SOC 2 CC6.1: Logical access security over protected information assets
  - ISO 27001 A.8.24: Use of cryptography

## Not in scope
<anything you did not check, e.g. infrastructure, dependencies>
```

Never print a full secret value. Show the first 4 characters and mask the rest.
