# Fix Examples

Use these when writing the **Fix** line of a finding. The examples are Python;
when the audited code is in another language, apply the same principle with
that language's standard library or framework.

A good fix:
- Shows the corrected code, not just advice ("use parameterized queries").
- Fixes the root cause, not the symptom (don't "sanitize" SQL input; use
  parameters).
- Is the smallest change that solves the problem.

---

## Hard-coded secret
**Principle:** load secrets from the environment or a secrets manager, and
rotate any secret that was ever committed. Deleting it from the code isn't
enough, because it stays in git history.

```python
# Bad
STRIPE_KEY = "sk_live_51Hxyz..."

# Good
import os
STRIPE_KEY = os.environ["STRIPE_KEY"]  # fails fast if missing
```
Always add to the fix: "Rotate this key now. It is in git history."

## SQL injection
**Principle:** pass user input as query parameters; never build SQL with
string formatting.

```python
# Bad
db.execute(f"SELECT * FROM users WHERE name = '{name}'")

# Good
db.execute("SELECT * FROM users WHERE name = ?", (name,))
```

## Command injection
**Principle:** don't use `shell=True` with user input. Pass arguments as a
list and validate the input.

```python
# Bad
subprocess.check_output(f"ping -c 1 {host}", shell=True)

# Good
import ipaddress
ipaddress.ip_address(host)  # raises ValueError if not a valid IP
subprocess.check_output(["ping", "-c", "1", host])
```

## `eval` / `exec` on user input
**Principle:** don't evaluate code from users. Parse data with a data parser.

```python
# Bad
config = eval(request.data)

# Good
import json
config = json.loads(request.data)
```

## Weak password hashing
**Principle:** use a slow, salted password hash (bcrypt, scrypt, argon2).
MD5 and SHA-1/256 are too fast and can be brute-forced.

```python
# Bad
hashlib.md5(password.encode()).hexdigest()

# Good
from werkzeug.security import generate_password_hash, check_password_hash
hashed = generate_password_hash(password)        # scrypt by default
check_password_hash(hashed, attempt)             # to verify
```

## Disabled TLS verification
**Principle:** never turn off certificate checks.

```python
# Bad
requests.get(url, verify=False)

# Good
requests.get(url)  # verification is on by default
```

## Missing authentication or authorization
**Principle:** every endpoint that changes or reveals data must check who the
caller is *and* whether they're allowed.

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

## Sensitive data in logs
**Principle:** never log passwords, tokens, or full card or ID numbers. Log
the event, not the secret.

```python
# Bad
log.info("new user password=%s", password)

# Good
log.info("new user registered: user_id=%s", user.id)
```

## Debug mode / insecure defaults
**Principle:** debug settings come from the environment and are off by
default.

```python
# Bad
app.run(debug=True, host="0.0.0.0")

# Good
import os
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
```
Add to the fix: "In production, run under gunicorn, not `app.run`."

## CORS allows any origin
**Principle:** allow only the origins that need access.

```python
# Bad
resp.headers["Access-Control-Allow-Origin"] = "*"
# or
CORS(app)

# Good
from flask_cors import CORS
CORS(app, origins=["https://app.example.com"])
```

## Vulnerable dependency
**Principle:** upgrade to the first fixed version the advisory names.

```
# Bad (requirements.txt)
flask==0.12

# Good
flask>=2.3.3   # first version fixing CVE-2023-30861
```
Name the CVE and the fixed version in the fix.
