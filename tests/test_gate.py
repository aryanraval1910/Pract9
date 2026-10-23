"""Unit tests for scripts/security_gate.py (policy + fail-closed behaviour)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import security_gate as gate  # noqa: E402


def write(d: Path, name: str, payload):
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def clean_reports(d: Path):
    write(d, "gitleaks-report.json", [])
    write(d, "bandit-report.json", {"results": []})
    write(d, "pip-audit-report.json", {"dependencies": [], "fixes": []})
    write(d, "hadolint-report.json", [])
    write(d, "trivy-report.json", {"Results": []})


def test_clean_reports_pass_in_enforce_mode(tmp_path):
    clean_reports(tmp_path)
    assert gate.main(["--reports-dir", str(tmp_path), "--mode", "enforce"]) == 0


def test_high_bandit_finding_blocks_in_enforce_but_not_report(tmp_path):
    clean_reports(tmp_path)
    write(tmp_path, "bandit-report.json", {"results": [{
        "issue_severity": "HIGH", "test_id": "B602", "filename": "a.py",
        "line_number": 1, "issue_text": "shell=True"}]})
    assert gate.main(["--reports-dir", str(tmp_path), "--mode", "enforce"]) == 1
    assert gate.main(["--reports-dir", str(tmp_path), "--mode", "report"]) == 0


def test_missing_report_fails_closed(tmp_path):
    clean_reports(tmp_path)
    (tmp_path / "trivy-report.json").unlink()
    assert gate.main(["--reports-dir", str(tmp_path), "--mode", "enforce"]) == 1


def test_pick_fix_prefers_installed_major_version():
    assert gate.pick_fix("1.26.9", ["1.26.19", "2.2.2"]) == "1.26.19"
    assert gate.pick_fix("2.2.2", ["2.2.3", "3.0.0"]) == "2.2.3"
    assert gate.pick_fix("1.0.0", ["2.0.0"]) == "2.0.0"


def test_gitleaks_report_never_exposes_secret_value(tmp_path, capsys):
    clean_reports(tmp_path)
    write(tmp_path, "gitleaks-report.json", [{
        "RuleID": "generic-api-key", "File": "x.py", "StartLine": 3,
        "Secret": "SUPER-SECRET-VALUE"}])
    gate.main(["--reports-dir", str(tmp_path)])
    assert "SUPER-SECRET-VALUE" not in capsys.readouterr().out


def test_trivy_only_blocks_on_fixable_critical(tmp_path):
    clean_reports(tmp_path)
    unfixable = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL", "PkgName": "libx",
         "InstalledVersion": "1"}]}]}
    write(tmp_path, "trivy-report.json", unfixable)
    assert gate.main(["--reports-dir", str(tmp_path), "--mode", "enforce"]) == 0
    unfixable["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = "2"
    write(tmp_path, "trivy-report.json", unfixable)
    assert gate.main(["--reports-dir", str(tmp_path), "--mode", "enforce"]) == 1
