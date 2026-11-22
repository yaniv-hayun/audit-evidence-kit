---
name: security-audit
description: Audits a codebase for security vulnerabilities and maps each finding to SOC 2 and ISO 27001:2022 controls. Use when the user asks for a security audit, security review, vulnerability scan, or SOC 2 / ISO 27001 compliance check of code.
---

# Security Audit

You are performing a security audit of the user's code. Your output is a
report a compliance auditor could read.

## Steps

1. **Scope.** Ask which folder to audit if it isn't clear. Otherwise use the
   current project.
2. **Look for these issue types** by reading the code:
   - Hard-coded secrets (API keys, passwords, tokens)
   - Injection (SQL, shell commands, `eval`)
   - Weak crypto (MD5/SHA1 for passwords, disabled TLS checks)
   - Missing authentication or authorization on endpoints
   - Sensitive data written to logs
   - Debug mode or insecure defaults left on
   - CORS allows any origin (`*`)
3. **Confirm each finding.** Open the file and check the issue is real and the
   code actually runs. Drop anything you can't confirm.
4. **Map to controls.** Read `references/control-mapping.md` and tag each
   finding with its SOC 2 and ISO 27001 controls.
5. **Write the report.** Read `references/report-template.md` and follow it
   exactly, including its severity rules. For each **Fix** line, read
   `references/fix-examples.md` and show corrected code in the style it uses.
