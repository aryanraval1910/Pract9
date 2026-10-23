"""VaultNotes - REMEDIATED version of app/main.py for the DevSecOps lab (PR9).

Each change maps to a finding in the pipeline report; see docs/REMEDIATION.md.
"""
import ast
import hashlib
import operator
import os
import sqlite3
import subprocess
import tempfile
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, jsonify, request

app = Flask(__name__)

# Secrets come from the environment (in CI: GitHub repository secrets).
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
PAYMENT_GATEWAY_API_KEY = os.environ.get("PAYMENT_GATEWAY_API_KEY", "")

DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(tempfile.gettempdir(), "vaultnotes.db")
)
ALLOWED_FETCH_HOSTS = {"example.org", "api.github.com"}


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
    """Parameterised query: user input is data, never SQL."""
    term = request.args.get("q", "")
    rows = get_db().execute(
        "SELECT id, owner, body FROM notes WHERE body LIKE ?", (f"%{term}%",)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/diag")
def diag():
    """Argument list, no shell: the input cannot become a second command."""
    name = request.args.get("name", "world")
    out = subprocess.run(  # nosec B603 B607 - fixed binary, no shell, list args
        ["echo", "diagnostic for", name], capture_output=True, text=True, check=False
    )
    return jsonify(output=out.stdout.strip())


_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


def _safe_eval(node):
    """Evaluate +, -, *, / over numbers only. Anything else is rejected."""
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    raise ValueError("unsupported expression")


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "0")
    try:
        return jsonify(result=_safe_eval(ast.parse(expr, mode="eval")))
    except (ValueError, SyntaxError, ZeroDivisionError):
        abort(400, description="invalid expression")


@app.get("/hash")
def hash_text():
    """SHA-256 instead of MD5."""
    text = request.args.get("text", "")
    return jsonify(sha256=hashlib.sha256(text.encode()).hexdigest())


@app.post("/config")
def load_config():
    """safe_load only builds plain data types."""
    data = yaml.safe_load(request.get_data())
    return jsonify(loaded=str(data))


@app.get("/fetch")
def fetch():
    """Allow-listed hosts, TLS verification on (default), bounded by a timeout."""
    url = request.args.get("url", "https://example.org")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        abort(400, description="host not allowed")
    resp = requests.get(url, timeout=5)
    return jsonify(status=resp.status_code, length=len(resp.content))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
