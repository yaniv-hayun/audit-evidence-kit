# Security Audit Report — vulnerable-app — 2026-11-23

**Scope:** `examples/vulnerable-app/` (`app.py`, `requirements.txt`)
**Scanned at:** 2026-11-23T19:10:58+00:00
**Method:** Automated scanning (gitleaks 8.30.1, semgrep 1.186.0,
osv-scanner 2.7.1), followed by manual verification of every scanner finding
and manual review for access control and logic flaws, performed by Claude
using the security-audit skill.

## Summary
11 findings: 7 high, 4 medium, 0 low
Scanner leads reviewed: 13 → 8 confirmed, 1 merged as duplicate, 4 false positives.

| # | Finding | Severity | Source | SOC 2 | ISO 27001 |
|---|---|---|---|---|---|
| 1 | Hard-coded Stripe live key | High | gitleaks + semgrep | CC6.1 | A.5.17, A.8.24 |
| 2 | SQL injection in `/user` | High | semgrep | CC7.1, CC8.1 | A.8.28 |
| 3 | Command injection in `/ping` | High | semgrep | CC7.1, CC8.1 | A.8.28 |
| 4 | Unsafe YAML deserialization in `/import` | High | semgrep | CC7.1, CC8.1 | A.8.28 |
| 5 | Unauthenticated admin action `/admin/delete-all` | High | manual review | CC6.1, CC6.3 | A.5.15, A.8.5 |
| 6 | Unauthenticated read of user records in `/user` | High | manual review | CC6.1, CC6.3 | A.5.15, A.8.5 |
| 7 | Vulnerable dependency: flask 0.12.2 | High | osv-scanner | CC7.1 | A.8.8 |
| 8 | Weak password hashing (MD5) | Medium | semgrep | CC6.1, CC6.7 | A.8.24 |
| 9 | Plaintext password written to logs | Medium | semgrep | CC6.1, CC7.2 | A.8.11, A.8.15 |
| 10 | Debug mode enabled, bound to all interfaces | Medium | semgrep | CC7.1, CC8.1 | A.8.9 |
| 11 | CORS allows any origin | Medium | manual review | CC6.6 | A.8.26 |

## Findings

### 1. Hard-coded Stripe live key — Severity: High
- **Location:** examples/vulnerable-app/app.py:18
- **Source:** gitleaks + semgrep, rule `stripe-access-token`
- **Evidence:** `STRIPE_KEY = "sk_l**********************"`
- **Why it matters:** Anyone with read access to the repository or its history
  gets a `sk_live_` key that can move money on the Stripe account. (The file
  comment says the value is fake; it is reported because it matches the live-key
  format and would be critical if real.)
- **Fix:**
  ```python
  # Bad
  STRIPE_KEY = "sk_live_..."

  # Good
  import os
  STRIPE_KEY = os.environ["STRIPE_KEY"]  # fails fast if missing
  ```
  Rotate this key now. It is in git history.
- **Controls:**
  - SOC 2 CC6.1: Logical access security over protected information assets
  - ISO 27001 A.5.17: Authentication information
  - ISO 27001 A.8.24: Use of cryptography

### 2. SQL injection in `/user` — Severity: High
- **Location:** examples/vulnerable-app/app.py:27 (input enters at :24)
- **Source:** semgrep, rules `sqlalchemy-execute-raw-query` (:27) and
  `sql-injection-db-cursor-execute` (:24), merged
- **Evidence:** `db.execute(f"SELECT * FROM users WHERE name = '{name}'")`
- **Why it matters:** An unauthenticated request such as
  `/user?name=' OR '1'='1` dumps the whole `users` table, and other payloads
  can read or alter any data in `app.db`.
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

### 3. Command injection in `/ping` — Severity: High
- **Location:** examples/vulnerable-app/app.py:34 (input enters at :32)
- **Source:** semgrep, rule `subprocess-injection`
- **Evidence:** `subprocess.check_output(f"ping -c 1 {host}", shell=True)`
- **Why it matters:** `/ping?host=127.0.0.1;id` runs arbitrary shell commands on
  the server, with no login required.
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

### 4. Unsafe YAML deserialization in `/import` — Severity: High
- **Location:** examples/vulnerable-app/app.py:52
- **Source:** semgrep, rule `insecure-deserialization`
- **Evidence:** `yaml.load(request.data, Loader=yaml.Loader)`
- **Why it matters:** `yaml.Loader` can construct arbitrary Python objects, so a
  POST body like `!!python/object/apply:os.system ["id"]` gives unauthenticated
  remote code execution.
- **Fix:**
  ```python
  # Bad
  yaml.load(request.data, Loader=yaml.Loader)

  # Good
  yaml.safe_load(request.data)
  ```
- **Controls:**
  - SOC 2 CC7.1: Detects configuration changes and new vulnerabilities
  - SOC 2 CC8.1: Changes are authorized, tested, and approved
  - ISO 27001 A.8.28: Secure coding

### 5. Unauthenticated admin action `/admin/delete-all` — Severity: High
- **Location:** examples/vulnerable-app/app.py:44-47
- **Source:** manual review
- **Evidence:** `sqlite3.connect("app.db").execute("DELETE FROM users")` with no
  login or role check on the route
- **Why it matters:** Any anonymous caller can delete every user with a single
  POST request.
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

### 6. Unauthenticated read of user records in `/user` — Severity: High
- **Location:** examples/vulnerable-app/app.py:22-27
- **Source:** manual review
- **Evidence:** `SELECT * FROM users ...` returned to any caller, no login check
- **Why it matters:** Even after the SQL injection (finding 2) is fixed, anyone
  can look up any user by name and receive every column of the row, including
  password hashes if stored there.
- **Fix:**
  ```python
  # Bad
  @app.route("/user")
  def get_user():
      ...
      return str(db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall())

  # Good
  from flask_login import login_required, current_user
  from flask import abort

  @app.route("/user")
  @login_required
  def get_user():
      name = request.args.get("name")
      if name != current_user.name and not current_user.is_admin:
          abort(403)
      db = sqlite3.connect("app.db")
      return str(db.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall())
  ```
- **Controls:**
  - SOC 2 CC6.1: Logical access security over protected information assets
  - SOC 2 CC6.3: Access is authorized, modified, or removed based on roles
  - ISO 27001 A.5.15: Access control
  - ISO 27001 A.8.5: Secure authentication

### 7. Vulnerable dependency: flask 0.12.2 — Severity: High
- **Location:** examples/vulnerable-app/requirements.txt (`flask==0.12.2`)
- **Source:** osv-scanner, advisories PYSEC-2018-66, PYSEC-2019-179,
  PYSEC-2023-62, PYSEC-2026-2151, GHSA-562c-5r94-xh97 (8 known vulnerabilities)
- **Evidence:** `flask==0.12.2` — CVE-2018-1000656, CVE-2019-1010083,
  CVE-2023-30861, CVE-2026-27205
- **Why it matters:** Flask is imported by `app.py` (line 9) and serves every
  request; the CVEs include remotely triggerable denial of service via crafted
  JSON and session-cookie disclosure through caching proxies.
- **Fix:**
  ```
  # Bad (requirements.txt)
  flask==0.12.2

  # Good
  flask>=3.1.3   # first version fixing all 8 advisories incl. CVE-2026-27205
  ```
  This is a major-version jump (0.x → 3.x); run the app's tests after upgrading.
- **Controls:**
  - SOC 2 CC7.1: Detects configuration changes and new vulnerabilities
  - ISO 27001 A.8.8: Management of technical vulnerabilities

### 8. Weak password hashing (MD5) — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:41
- **Source:** semgrep, rule `md5-used-as-password`
- **Evidence:** `hashlib.md5(password.encode()).hexdigest()`
- **Why it matters:** Unsalted MD5 is cracked at billions of guesses per second,
  so any leak of the hashes (e.g. via finding 2) exposes users' passwords.
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

### 9. Plaintext password written to logs — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:40
- **Source:** semgrep, rule `python-logger-credential-disclosure`
- **Evidence:** `log.info("new user password=%s", password)`
- **Why it matters:** Every new user's password lands in plaintext in log files
  and any log aggregation system, readable by anyone with log access.
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

### 10. Debug mode enabled, bound to all interfaces — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:56
- **Source:** semgrep, rule `avoid_app_run_with_bad_host`
- **Evidence:** `app.run(debug=True, host="0.0.0.0")`
- **Why it matters:** The Werkzeug interactive debugger is exposed on every
  network interface; combined with a leaked or guessed debugger PIN it gives
  code execution, and stack traces leak source and config.
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

### 11. CORS allows any origin — Severity: Medium
- **Location:** examples/vulnerable-app/app.py:13-16
- **Source:** manual review
- **Evidence:** `resp.headers["Access-Control-Allow-Origin"] = "*"`
- **Why it matters:** Any website can make a visitor's browser call this API
  and read the responses, which widens the reach of findings 2, 3 and 6.
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

## False positives
| Scanner | Location | Rule | Why it was dropped |
|---|---|---|---|
| semgrep | app.py:24 | sql-injection-db-cursor-execute | Duplicate of finding 2 (source line of the same SQL injection) |
| osv-scanner | requirements.txt (requests 2.19.0) | PYSEC-2018-28 et al. (10 vulns) | `requests` is declared but never imported; not reachable. Remove it from requirements.txt |
| osv-scanner | requirements.txt (urllib3 1.23.0) | PYSEC-2019-132 et al. (24 vulns) | Transitive dependency of unused `requests` only; not reachable |
| osv-scanner | requirements.txt (idna 2.7.0) | PYSEC-2024-60 et al. (4 vulns) | Transitive dependency of unused `requests` only; not reachable |
| osv-scanner | requirements.txt (certifi 2026.7.22) | PYSEC-2026-4320, GHSA-6q48-6c7w-9gw2 | Transitive dependency of unused `requests` only; not reachable |

## Limitations
- All three scanners ran successfully; no scanner gaps.
- `pyyaml` is imported by `app.py` but not listed in `requirements.txt`, so
  osv-scanner could not check its version. Pin it (e.g. `pyyaml>=6.0.2`) and
  re-scan.
- The four dropped dependency findings are unreachable from current code but
  would still be installed in any environment built from `requirements.txt`;
  removing `requests` eliminates them.
- No CSRF finding: the app uses no cookie-based sessions or HTML forms, so CSRF
  does not apply today. Re-check once authentication (findings 5, 6) is added.
- Not checked: infrastructure, cloud configuration, database schema and
  contents of `app.db`, and runtime behavior (no dynamic testing performed).
