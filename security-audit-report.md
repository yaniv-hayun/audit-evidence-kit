# Security Audit Report — audit-evidence-kit — 2026-11-22

**Scope:** `audit-evidence-kit/` (the only application code is `examples/vulnerable-app/app.py`)
**Method:** Manual code review by Claude using the security-audit skill.

## Summary
8 findings: 4 high, 4 medium, 0 low

| # | Finding | Severity | SOC 2 | ISO 27001 |
|---|---|---|---|---|
| 1 | SQL injection in `/user` | High | CC7.1, CC8.1 | A.8.28 |
| 2 | Command injection in `/ping` | High | CC7.1, CC8.1 | A.8.28 |
| 3 | Unauthenticated admin action `/admin/delete-all` | High | CC6.1, CC6.3 | A.5.15, A.8.5 |
| 4 | Hard-coded Stripe live key | High | CC6.1 | A.5.17, A.8.24 |
| 5 | Weak password hashing (MD5) | Medium | CC6.1, CC6.7 | A.8.24 |
| 6 | Plaintext password written to logs | Medium | CC6.1, CC7.2 | A.8.11, A.8.15 |
| 7 | Debug mode on, bound to all interfaces | Medium | CC7.1, CC8.1 | A.8.9 |
| 8 | CORS allows any origin | Medium | CC6.6 | A.8.26 |

## Findings

### 1. SQL injection in `/user` — Severity: High
- **Location:** examples/vulnerable-app/app.py:26
- **Evidence:** `db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()`
- **Why it matters:** Any unauthenticated caller can send `?name=' OR '1'='1` to dump the whole `users` table, or alter the query further.
- **Fix:**
  ```python
  # Bad
  db.execute(f"SELECT * FROM users WHERE name = '{name}'")

  # Good
  db.execute("SELECT * FROM users WHERE name = ?", (name,))
  ```
- **Controls:**
  - SOC 2 CC7.1: Detects configuration changes and new vulnerabilities
  - SOC 2 CC8.1: Changes are authorized, tested, and approved
  - ISO 27001 A.8.28: Secure coding

### 2. Command injection in `/ping` — Severity: High
- **Location:** examples/vulnerable-app/app.py:33
- **Evidence:** `subprocess.check_output(f"ping -c 1 {host}", shell=True)`
- **Why it matters:** An unauthenticated caller can run arbitrary shell commands on the server, e.g. `?host=127.0.0.1;cat /etc/passwd`.
- **Fix:**
  ```python
  # Bad
  subprocess.check_output(f"ping -c 1 {host}", shell=True)

  # Good
  import ipaddress
  ipaddress.ip_address(host)  # raises ValueError if not a valid IP
  subprocess.check_output(["ping", "-c", "1", host])
  ```
- **Controls:**
  - SOC 2 CC7.1: Detects configuration changes and new vulnerabilities
  - SOC 2 CC8.1: Changes are authorized, tested, and approved
  - ISO 27001 A.8.28: Secure coding

### 3. Unauthenticated admin action `/admin/delete-all` — Severity: High
- **Location:** examples/vulnerable-app/app.py:43-46
- **Evidence:** `def delete_all():  # no authentication check` → `sqlite3.connect("app.db").execute("DELETE FROM users")`
- **Why it matters:** Anyone who can reach the server can call a destructive admin endpoint with no login or role check. Note: the code never calls `commit()`, so today sqlite rolls the delete back when the connection closes; the access-control gap is real regardless, and adding the missing `commit()` would make it wipe all users.
- **Fix:**
  ```python
  # Bad
  @app.route("/admin/delete-all", methods=["POST"])
  def delete_all():
      ...

  # Good
  from flask_login import login_required, current_user
  from flask import abort

  @app.route("/admin/delete-all", methods=["POST"])
  @login_required
  def delete_all():
      if not current_user.is_admin:
          abort(403)
      ...
  ```
- **Controls:**
  - SOC 2 CC6.1: Logical access security over protected information assets
  - SOC 2 CC6.3: Access is authorized, modified, or removed based on roles
  - ISO 27001 A.5.15: Access control
  - ISO 27001 A.8.5: Secure authentication

### 4. Hard-coded Stripe live key — Severity: High
- **Location:** examples/vulnerable-app/app.py:17
- **Evidence:** `STRIPE_KEY = "sk_l****************************"`
- **Why it matters:** A `sk_live_` key in source gives anyone with repo access full control of the Stripe account. (The file header states this key is fake; it is rated as a live key because of its format.)
- **Fix:**
  ```python
  # Bad
  STRIPE_KEY = "sk_l****..."

  # Good
  import os
  STRIPE_KEY = os.environ["STRIPE_KEY"]  # fails fast if missing
  ```
  Rotate this key now. Once committed it is in git history; this file is currently untracked, so remove the key before the first commit.
- **Controls:**
  - SOC 2 CC6.1: Logical access security over protected information assets
  - ISO 27001 A.5.17: Authentication information
  - ISO 27001 A.8.24: Use of cryptography

### 5. Weak password hashing (MD5) — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:40
- **Evidence:** `return hashlib.md5(password.encode()).hexdigest()`
- **Why it matters:** Unsalted MD5 is cracked in seconds with commodity GPUs once hashes leak (for example via finding 1). The endpoint also returns the hash to the caller.
- **Fix:**
  ```python
  # Bad
  hashlib.md5(password.encode()).hexdigest()

  # Good
  from werkzeug.security import generate_password_hash, check_password_hash
  hashed = generate_password_hash(password)        # scrypt by default
  check_password_hash(hashed, attempt)             # to verify
  ```
- **Controls:**
  - SOC 2 CC6.1: Logical access security over protected information assets
  - SOC 2 CC6.7: Restricts and protects data in transmission and movement
  - ISO 27001 A.8.24: Use of cryptography

### 6. Plaintext password written to logs — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:39
- **Evidence:** `log.info("new user password=%s", password)`
- **Why it matters:** Every registered password lands in plaintext in log files and log pipelines. With no logging config, Python drops INFO messages, so this leaks as soon as INFO logging is enabled (common under gunicorn or a log shipper).
- **Fix:**
  ```python
  # Bad
  log.info("new user password=%s", password)

  # Good
  log.info("new user registered: user_id=%s", user.id)
  ```
- **Controls:**
  - SOC 2 CC6.1: Logical access security over protected information assets
  - SOC 2 CC7.2: Monitors system components for anomalies
  - ISO 27001 A.8.11: Data masking
  - ISO 27001 A.8.15: Logging

### 7. Debug mode on, bound to all interfaces — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:50
- **Evidence:** `app.run(debug=True, host="0.0.0.0")`
- **Why it matters:** The Werkzeug debugger is reachable from the network and offers an interactive Python console (code execution) if its PIN is obtained; tracebacks also leak source and config.
- **Fix:**
  ```python
  # Bad
  app.run(debug=True, host="0.0.0.0")

  # Good
  import os
  app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
  ```
  In production, run under gunicorn, not `app.run`.
- **Controls:**
  - SOC 2 CC7.1: Detects configuration changes and new vulnerabilities
  - SOC 2 CC8.1: Changes are authorized, tested, and approved
  - ISO 27001 A.8.9: Configuration management

### 8. CORS allows any origin — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:14
- **Evidence:** `resp.headers["Access-Control-Allow-Origin"] = "*"`
- **Why it matters:** Any website can read this API's responses from a visitor's browser, which helps attackers chain findings 1 and 2 from a malicious page.
- **Fix:**
  ```python
  # Bad
  resp.headers["Access-Control-Allow-Origin"] = "*"

  # Good
  from flask_cors import CORS
  CORS(app, origins=["https://app.example.com"])
  ```
- **Controls:**
  - SOC 2 CC6.6: Protection against threats from outside system boundaries
  - ISO 27001 A.8.26: Application security requirements

## Not in scope
- Dependencies: there is no `requirements.txt` or lockfile, so no vulnerable-dependency check was possible.
- Infrastructure, deployment, TLS termination, and network configuration.
- Git history (the repository has no commits yet).
- Runtime/dynamic testing: findings come from reading code, not from running exploits.
- `.claude/skills/` (skill instructions and reference docs, not application code).
