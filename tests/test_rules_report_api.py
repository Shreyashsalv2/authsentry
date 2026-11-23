import json
import os
import subprocess
import sys
from datetime import datetime

import pytest

from authsentry import analyze_text, to_dict, to_markdown
from authsentry.rules import load_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "api"))
import analyze as api  # noqa: E402

LINUX = open(os.path.join(ROOT, "samples", "linux_auth.log")).read()


def write(tmp_path, body):
    p = tmp_path / "rules.yaml"
    p.write_text(body)
    return str(p)


def test_default_rules_load_with_attack_ids():
    rs = load_rules()
    assert [r.id for r in rs.rules] == ["AS-001", "AS-002", "AS-003", "AS-004"]
    assert {r.attack["technique"] for r in rs.rules} == {"T1110.001", "T1110.003", "T1078", "T1110"}
    assert set(rs.escalation) == {"critical", "high", "medium", "low"}


@pytest.mark.parametrize("bad", [
    "rules: [{id: X, name: n, type: magic, severity: high, group_by: [src_ip], threshold: 1, window_minutes: 1, attack: {technique: T1110}}]",
    "rules: [{id: X, name: n, type: threshold, severity: urgent, group_by: [src_ip], threshold: 1, window_minutes: 1, attack: {technique: T1110}}]",
    "rules: [{id: X, name: n, type: threshold, severity: high, group_by: [password], threshold: 1, window_minutes: 1, attack: {technique: T1110}}]",
    "rules: [{id: X, name: n, type: distinct, severity: high, group_by: [src_ip], threshold: 2, window_minutes: 1, attack: {technique: T1110}}]",
    "rules: [{id: X, name: n, type: threshold, severity: high, group_by: [src_ip], threshold: 0, window_minutes: 1, attack: {technique: T1110}}]",
    "rules: [{id: X, name: n, type: threshold, severity: high, group_by: [src_ip], threshold: 1, window_minutes: 1, attack: {technique: brute}}]",
    "rules: []",
])
def test_bad_rules_are_rejected(tmp_path, bad):
    with pytest.raises(ValueError):
        load_rules(write(tmp_path, bad))


def test_custom_rule_file_changes_threshold(tmp_path):
    path = write(tmp_path, """
rules:
  - {id: T-1, name: Any two failures, type: threshold, outcome: failure, group_by: [src_ip], threshold: 2,
     window_minutes: 60, severity: low, attack: {technique: T1110, name: Brute Force, tactic: Credential Access}}
""")
    result = analyze_text(LINUX, year=2026, ruleset=load_rules(path))
    assert {a.rule_id for a in result.alerts} == {"T-1"}
    assert {ip for a in result.alerts for ip in a.values("src_ip")} >= {"203.0.113.45", "198.51.100.23", "203.0.113.99"}


def test_markdown_report_has_incidents_attack_links_and_evidence():
    md = to_markdown(analyze_text(LINUX, year=2026), generated=datetime(2026, 11, 23, 12, 0))
    assert md.startswith("# AuthSentry incident report")
    assert "## INC-0001 · CRITICAL · Successful login after repeated failures" in md
    assert "https://attack.mitre.org/techniques/T1110/003/" in md
    assert "Failed password for root from 203.0.113.45 port 41200 ssh2" in md
    assert "Escalate to L2 / incident response now" in md


def test_markdown_for_clean_log():
    md = to_markdown(analyze_text("Nov 23 09:00:01 web01 sshd[1]: Accepted publickey for a from 192.0.2.1 port 1 ssh2", year=2026))
    assert "No rule fired" in md


def test_json_report_limits_evidence():
    many = "\n".join(f"Nov 23 09:00:{i:02d} web01 sshd[{i}]: Failed password for root from 203.0.113.45 port {i} ssh2" for i in range(30))
    d = to_dict(analyze_text(many, year=2026))
    a = d["alerts"][0]
    assert a["event_count"] == 30 and len(a["evidence"]) == 10 and a["evidence_omitted"] == 20
    assert d["summary"]["top_failing_sources"][0] == {"src_ip": "203.0.113.45", "failures": 30}


def test_api_handle_ok():
    status, body = api.handle(json.dumps({"log": LINUX, "year": 2026}).encode())
    assert status == 200
    assert body["summary"]["alerts"] == 3 and body["markdown"].startswith("# AuthSentry")


@pytest.mark.parametrize("body,ctype,code", [
    (b"not json", "application/json", 400),
    (b"[1,2]", "application/json", 400),
    (json.dumps({"log": "   "}).encode(), "application/json", 400),
    (json.dumps({"log": "x", "year": "soon"}).encode(), "application/json", 400),
    (json.dumps({"log": "x", "format": "splunk"}).encode(), "application/json", 400),
    (json.dumps({"log": "[{broken"}).encode(), "application/json", 400),
    (json.dumps({"log": "x"}).encode(), "text/plain", 415),
    (b"x" * (api.MAX_BYTES + 1), "application/json", 413),
])
def test_api_rejects_bad_input(body, ctype, code):
    status, out = api.handle(body, ctype)
    assert status == code and "error" in out


def test_cli_markdown_json_and_fail_on(tmp_path):
    sample = os.path.join(ROOT, "samples", "linux_auth.log")
    run = lambda *a: subprocess.run([sys.executable, "-m", "authsentry", sample, "--year", "2026", *a],
                                    cwd=ROOT, capture_output=True, text=True)
    r = run()
    assert r.returncode == 0 and "INC-0003" in r.stdout
    out = tmp_path / "r.json"
    assert run("--json", "-o", str(out)).returncode == 0
    assert json.loads(out.read_text())["summary"]["alerts"] == 3
    assert run("--fail-on", "critical").returncode == 2
