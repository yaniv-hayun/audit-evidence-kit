# DELIBERATELY VULNERABLE — test target for the security-audit skill.
# Do not deploy. The "secrets" below are fake.
import hashlib
import logging
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"  # CORS open to any origin
    return resp
    
STRIPE_KEY = "sk_live_FAKE51HxyzABCDEF0123456789"  # hard-coded secret
log = logging.getLogger(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name")
    db = sqlite3.connect("app.db")
    # SQL injection: user input concatenated into the query
    return str(db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    log.info("new user password=%s", password)  # sensitive data in logs
    return hashlib.md5(password.encode()).hexdigest()  # weak password hashing


@app.route("/admin/delete-all", methods=["POST"])
def delete_all():  # no authentication check
    sqlite3.connect("app.db").execute("DELETE FROM users")
    return "ok"


@app.route("/import", methods=["POST"])
def import_config():
    return str(yaml.load(request.data, Loader=yaml.Loader))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")  # debug mode on

