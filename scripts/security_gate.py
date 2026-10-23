#!/usr/bin/env python3
"""Security gate for the PR9 DevSecOps pipeline.

Reads the JSON reports produced by the individual scanner jobs, prints a
Markdown summary (also appended to the GitHub job summary when available) and
decides whether the build may continue.

Policy (what counts as a gate violation)
    Gitleaks   any leaked secret
    Bandit     any finding with severity HIGH
    pip-audit  any vulnerable dependency that has a fixed version available
    Trivy      any CRITICAL vulnerability in the image that has a fixed version
               (unfixable CVEs are listed but cannot block you: nothing to act on)
    Hadolint   any finding with level "error"

Modes
    report   always exit 0, but still say whether the gate *would* have failed
    enforce  exit 1 on a violation, or when a scanner report is missing/corrupt
             (fail closed: a scan that never ran must not look like a clean scan)

Secrets are never printed: Gitleaks entries show rule, file and line only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

MAX_ROWS = 10  # rows shown per scanner in the detail tables


def load_json(path: Path):
    """Return (data, error). error is None on success."""
    if not path.is_file():
        return None, "report not found (scan did not run or failed)"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, ValueError) as exc:
        return None, f"report unreadable: {exc}"


def _result(name, rule, error=None, counts=None, violations=0, rows=None, header=None):
    return {
        "name": name,
        "rule": rule,
        "error": error,
        "counts": counts or {},
        "violations": violations,
        "rows": rows or [],
        "header": header or [],
    }


def check_gitleaks(path: Path):
    rule = "no leaked secrets"
    data, err = load_json(path)
    if err:
        return _result("Gitleaks", rule, error=err)
    if not isinstance(data, list):
        return _result("Gitleaks", rule, error="unexpected report format")
    rows = [
        [f.get("RuleID", "?"), f.get("File", "?"), str(f.get("StartLine", "?"))]
        for f in data
    ]
    return _result(
        "Gitleaks", rule,
        counts={"leaks": len(data)},
        violations=len(data),
        rows=rows[:MAX_ROWS],
        header=["Rule", "File", "Line"],
    )


def check_bandit(path: Path):
    rule = "0 findings with severity HIGH"
    data, err = load_json(path)
    if err:
        return _result("Bandit", rule, error=err)
    if "results" not in data:
        return _result("Bandit", rule, error="unexpected report format")
    results = data["results"]
    counts = Counter(r.get("issue_severity", "UNKNOWN") for r in results)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    top = sorted(results, key=lambda r: order.get(r.get("issue_severity"), 3))
    rows = [
        [r["issue_severity"], r["test_id"], f'{r["filename"]}:{r["line_number"]}',
         r["issue_text"][:80]]
        for r in top[:MAX_ROWS]
    ]
    return _result(
        "Bandit", rule,
        counts={k: counts.get(k, 0) for k in ("HIGH", "MEDIUM", "LOW")},
        violations=counts.get("HIGH", 0),
        rows=rows,
        header=["Severity", "Test", "Location", "Issue"],
    )


def _ver(text: str):
    return [int(p) if p.isdigit() else 0 for p in text.split(".")]


def pick_fix(installed: str, fix_versions: list[str]) -> str:
    """Smallest upgrade that fixes a vuln, preferring the installed major version.

    pip-audit lists fixes for every release branch (e.g. 1.26.19 AND 2.2.2);
    recommending the 2.x line to someone on 1.x would be needless churn.
    """
    same_major = [v for v in fix_versions if _ver(v)[0] == _ver(installed)[0]]
    return min(same_major or fix_versions, key=_ver)


def check_pip_audit(path: Path):
    rule = "0 vulnerable packages with a fix available"
    data, err = load_json(path)
    if err:
        return _result("pip-audit", rule, error=err)
    if "dependencies" not in data:
        return _result("pip-audit", rule, error="unexpected report format")
    total = fixable = 0
    pkgs = 0
    rows = []
    for dep in data["dependencies"]:
        vulns = dep.get("vulns") or []
        if not vulns:
            continue
        pkgs += 1
        total += len(vulns)
        has_fix = [v for v in vulns if v.get("fix_versions")]
        fixable += len(has_fix)
        needed = [pick_fix(dep["version"], v["fix_versions"]) for v in has_fix]
        best_fix = max(needed, key=_ver) if needed else "-"
        rows.append([dep["name"], dep["version"], str(len(vulns)), best_fix])
    rows.sort(key=lambda r: -int(r[2]))
    return _result(
        "pip-audit", rule,
        counts={"packages": pkgs, "vulns": total, "fixable": fixable},
        violations=fixable,
        rows=rows[:MAX_ROWS],
        header=["Package", "Installed", "Vulns", "Upgrade to (clears all)"],
    )


def check_trivy(path: Path):
    rule = "0 CRITICAL vulnerabilities with a fix available"
    data, err = load_json(path)
    if err:
        return _result("Trivy", rule, error=err)
    if "Results" not in data:
        # Trivy omits "Results" entirely when nothing was found.
        data = {"Results": []}
    vulns = [v for r in data["Results"] for v in (r.get("Vulnerabilities") or [])]
    counts = Counter(v.get("Severity", "UNKNOWN") for v in vulns)
    crit = [v for v in vulns if v.get("Severity") == "CRITICAL"]
    fixable = [v for v in crit if v.get("FixedVersion")]
    # Show fixable ones first: those are the ones you can act on.
    crit.sort(key=lambda v: not v.get("FixedVersion"))
    rows = [
        [v.get("VulnerabilityID", "?"), v.get("PkgName", "?"),
         v.get("InstalledVersion", "?"), v.get("FixedVersion") or "no fix yet"]
        for v in crit[:MAX_ROWS]
    ]
    return _result(
        "Trivy", rule,
        counts={**{k: counts.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
                "critical fixable": len(fixable)},
        violations=len(fixable),
        rows=rows,
        header=["CRITICAL CVE", "Package", "Installed", "Fixed in"],
    )


def check_hadolint(path: Path):
    rule = "0 findings with level error"
    data, err = load_json(path)
    if err:
        return _result("Hadolint", rule, error=err)
    if not isinstance(data, list):
        return _result("Hadolint", rule, error="unexpected report format")
    counts = Counter(f.get("level", "unknown") for f in data)
    rows = [[f.get("level", "?"), f.get("code", "?"), str(f.get("line", "?")),
             f.get("message", "")[:80]] for f in data[:MAX_ROWS]]
    return _result(
        "Hadolint", rule,
        counts={k: counts.get(k, 0) for k in ("error", "warning", "info", "style")},
        violations=counts.get("error", 0),
        rows=rows,
        header=["Level", "Code", "Line", "Message"],
    )


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(c.replace("|", "\\|") for c in row) + " |" for row in rows]
    return "\n".join(out)


def render(results, mode):
    failed = [r for r in results if r["error"] or r["violations"]]
    lines = [f"## DevSecOps security gate (mode: `{mode}`)", ""]
    summary_rows = []
    for r in results:
        if r["error"]:
            status, found = "MISSING", r["error"]
        else:
            status = "FAIL" if r["violations"] else "PASS"
            found = ", ".join(f"{k}: {v}" for k, v in r["counts"].items())
        summary_rows.append([r["name"], status, found, r["rule"]])
    lines.append(table(["Scanner", "Status", "Findings", "Gate rule"], summary_rows))
    for r in results:
        if r["rows"]:
            lines += ["", f"### {r['name']} - top findings", "", table(r["header"], r["rows"])]
    lines.append("")
    if failed:
        verdict = "BLOCKED" if mode == "enforce" else "WOULD BE BLOCKED (report mode)"
    else:
        verdict = "PASSED"
    lines.append(f"**Gate verdict: {verdict}**")
    return "\n".join(lines), bool(failed)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reports-dir", default="reports", type=Path)
    ap.add_argument("--mode", choices=["report", "enforce"], default="report")
    args = ap.parse_args(argv)

    d = args.reports_dir
    results = [
        check_gitleaks(d / "gitleaks-report.json"),
        check_bandit(d / "bandit-report.json"),
        check_pip_audit(d / "pip-audit-report.json"),
        check_hadolint(d / "hadolint-report.json"),
        check_trivy(d / "trivy-report.json"),
    ]
    markdown, failed = render(results, args.mode)
    print(markdown)

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")

    if failed and args.mode == "enforce":
        print("\nGate failed: fix the findings above or review the policy.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
