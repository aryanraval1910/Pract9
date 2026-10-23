"""VaultNotes - a DELIBERATELY INSECURE demo API for the DevSecOps lab (PR9).

Every weakness below is intentional so that the scanners in the pipeline have
something real to find. Each one is tagged with the rule that should catch it.

    !!  Do NOT deploy this anywhere reachable from the internet.  !!
"""
import hashlib
import os
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

# [Bandit B105] hard-coded secret used for session signing.
app.config["SECRET_KEY"] = "vaultnotes-dev-secret-2026"

# [Gitleaks generic-api-key] fake credential committed to source control.
PAYMENT_GATEWAY_API_KEY = "pgw_live_k8Hs92LmQp7XvT4zRn1BdW6yUe3JcA5o"

DB_PATH = os.environ.get("DB_PATH", "/tmp/vaultnotes.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS notes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, body TEXT)"
        )
        if conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO notes (owner, body) VALUES (?, ?)",
                [
                    ("alice", "buy milk"),
                    ("alice", "renew passport"),
                    ("bob", "deploy friday (never)"),
                ],
            )


init_db()


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/notes")
def search_notes():
    """[Bandit B608] SQL built with an f-string -> SQL injection."""
    term = request.args.get("q", "")
    query = f"SELECT id, owner, body FROM notes WHERE body LIKE '%{term}%'"
    rows = get_db().execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/diag")
def diag():
    """[Bandit B602] shell=True with user input -> command injection."""
    name = request.args.get("name", "world")
    out = subprocess.run(
        f"echo diagnostic for {name}", shell=True, capture_output=True, text=True
    )
    return jsonify(output=out.stdout.strip())


@app.get("/calc")
def calc():
    """[Bandit B307] eval() on user input -> arbitrary code execution."""
    expr = request.args.get("expr", "0")
    return jsonify(result=eval(expr))


@app.get("/hash")
def hash_text():
    """[Bandit B324] MD5 is a broken hash for anything security related."""
    text = request.args.get("text", "")
    return jsonify(md5=hashlib.md5(text.encode()).hexdigest())


@app.post("/config")
def load_config():
    """[Bandit B506] yaml.load with the full Loader -> object instantiation."""
    data = yaml.load(request.get_data(), Loader=yaml.Loader)
    return jsonify(loaded=str(data))


@app.get("/fetch")
def fetch():
    """[Bandit B501 + B113] TLS verification off, no timeout, user-chosen URL."""
    url = request.args.get("url", "https://example.org")
    resp = requests.get(url, verify=False)
    return jsonify(status=resp.status_code, length=len(resp.content))


if __name__ == "__main__":
    # [Bandit B201 + B104] debug server bound to every interface.
    app.run(host="0.0.0.0", port=8000, debug=True)
