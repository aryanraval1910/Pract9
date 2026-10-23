# Remediation guide

How each finding from the pipeline was fixed in `docs/fixed/`. Every fix was
re-scanned: 13 tests pass, Bandit reports 0 HIGH / 0 MEDIUM, pip-audit and
Gitleaks are clean.

## Triage first

Severity says how bad it is if exploited; confidence says how sure the tool is.
Fix HIGH severity first. Treat LOW confidence as "verify before spending time"
(for example Bandit's B608 SQL finding is LOW confidence, but here it is a real
injection). Don't suppress findings to make the build green; if you accept a risk,
say why in a `# nosec` comment, as `/diag` does after its fix.

## Code findings (Bandit / Gitleaks)

| Finding | Where | Risk | Fix |
|---|---|---|---|
| B602 `shell=True` | `/diag` | input like `x; rm -rf ...` runs as a command | `subprocess.run(["echo", ..., name])`: argument list, no shell |
| B324 MD5 | `/hash` | collisions are practical; unsuitable for security use | `hashlib.sha256` |
| B501 `verify=False` | `/fetch` | disables TLS checks, enabling man-in-the-middle | remove it (verification is the default) |
| B113 no timeout | `/fetch` | a slow server can hang a worker forever | `timeout=5` |
| B201 `debug=True` | `__main__` | Werkzeug debugger allows remote code execution | remove `debug`; bind to `127.0.0.1` for dev (also clears B104) |
| B608 SQL f-string | `/notes` | SQL injection (`' OR '1'='1` returns every row) | parameterised query `LIKE ?` |
| B307 `eval` | `/calc` | arbitrary code execution | small AST evaluator allowing only `+ - * /` on numbers |
| B506 `yaml.load` | `/config` | YAML can construct arbitrary Python objects | `yaml.safe_load` |
| B105 hard-coded secret / Gitleaks `generic-api-key` | module top | secrets in git are readable forever | read from environment; **rotate the leaked value** |
| B108 `/tmp` path | `DB_PATH` | predictable temp path | `tempfile.gettempdir()` |
| SSRF (no scanner flags this) | `/fetch` | server can be pointed at internal addresses | https-only host allow-list |

The fixed test suite includes regression tests for the injection fixes. They fail
on the vulnerable code, which is what a good security test should do.

## Dependency findings (pip-audit / Trivy library layer)

`docs/fixed/requirements.txt` bumps every package to a release with no known
advisories at the time of writing (Flask 3.1.3, Werkzeug 3.1.9, Jinja2 3.1.6,
requests 2.34.2, urllib3 2.8.0, gunicorn 26.2.0, ...). Major-version jumps
(Flask 2 to 3, urllib3 1 to 2) can break things in real projects, so the tests
are what make such upgrades safe.

## Image findings (Trivy OS layer)

Base-image CVEs are usually fixed by rebuilding on a fresh `python:3.12-slim`;
the weekly scheduled run exists to tell you when that is needed. Findings with
"no fix yet" can't be patched; the policy decides whether they block you.
