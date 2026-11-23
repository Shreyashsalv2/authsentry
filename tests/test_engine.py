import os
from datetime import datetime, timedelta

import pytest

from authsentry import analyze_text
from authsentry.engine import detect, fmt_span
from authsentry.models import AuthEvent
from authsentry.rules import load_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = load_rules()
T0 = datetime(2026, 11, 23, 9, 0, 0)


def ev(sec, outcome="failure", user="root", ip="203.0.113.45", host="web01", n=0):
    return AuthEvent(timestamp=T0 + timedelta(seconds=sec), source="linux-sshd", host=host, outcome=outcome,
                     user=user, src_ip=ip, line_no=n or sec + 1, raw=f"{outcome} {user} {ip}")


def rule_ids(alerts):
    return sorted(a.rule_id for a in alerts)


def test_brute_force_fires_at_threshold_not_below():
    assert rule_ids(detect([ev(i * 10) for i in range(4)], RULES)) == []
    alerts = detect([ev(i * 10) for i in range(5)], RULES)
    assert rule_ids(alerts) == ["AS-001"]
    assert len(alerts[0].events) == 5 and alerts[0].severity == "high"


def test_failures_outside_the_window_do_not_fire():
    # 5 failures, 2 minutes apart: never 5 inside one 5-minute window
    assert detect([ev(i * 120) for i in range(5)], RULES) == []


def test_long_attack_is_one_incident():
    alerts = detect([ev(i * 30) for i in range(40)], RULES)
    assert rule_ids(alerts) == ["AS-001"]
    assert len(alerts[0].events) == 40


def test_separate_bursts_are_separate_incidents():
    first = [ev(i * 10) for i in range(5)]
    second = [ev(3600 + i * 10) for i in range(5)]
    assert rule_ids(detect(first + second, RULES)) == ["AS-001", "AS-001"]


def test_password_spray_needs_distinct_accounts():
    same_user = [ev(i * 20, user="root") for i in range(4)]
    assert "AS-002" not in rule_ids(detect(same_user, RULES))
    spray = [ev(i * 20, user=u) for i, u in enumerate(["admin", "oracle", "test", "ubuntu"])]
    alerts = detect(spray, RULES)
    assert rule_ids(alerts) == ["AS-002"]
    assert alerts[0].values("user") == ["admin", "oracle", "test", "ubuntu"]
    assert "4 different accounts" in alerts[0].detail


def test_success_after_failures_is_critical():
    events = [ev(0), ev(10), ev(20), ev(30, outcome="success")]
    alerts = detect(events, RULES)
    assert rule_ids(alerts) == ["AS-003"]
    assert alerts[0].severity == "critical" and alerts[0].attack["technique"] == "T1078"
    assert alerts[0].events[-1].outcome == "success"


def test_typo_then_success_does_not_fire():
    assert detect([ev(0, ip="192.0.2.10", user="bob"), ev(20, "success", "bob", "192.0.2.10")], RULES) == []


def test_success_from_other_ip_does_not_fire():
    events = [ev(0), ev(10), ev(20), ev(30, outcome="success", ip="192.0.2.10")]
    assert detect(events, RULES) == []


def test_lockout_burst():
    locks = [ev(i * 60, outcome="lockout", user=u, ip="", host="DC01") for i, u in enumerate(["a", "b", "c"])]
    alerts = detect(locks, RULES)
    assert rule_ids(alerts) == ["AS-004"]
    assert alerts[0].severity == "medium"


def test_alerts_sorted_by_severity_and_numbered():
    events = [ev(i * 10) for i in range(5)] + [ev(60, outcome="success")]
    alerts = detect(events, RULES)
    assert [a.severity for a in alerts] == ["critical", "high"]
    assert [a.incident_id for a in alerts] == ["INC-0001", "INC-0002"]


def test_linux_sample_end_to_end():
    text = open(os.path.join(ROOT, "samples", "linux_auth.log")).read()
    result = analyze_text(text, year=2026)
    got = {(a.rule_id, ", ".join(a.values("src_ip"))) for a in result.alerts}
    assert got == {("AS-001", "203.0.113.45"), ("AS-002", "198.51.100.23"), ("AS-003", "198.51.100.23")}
    # benign activity (192.0.2.10) and slow guessing (203.0.113.99) must not alert
    assert not any("192.0.2.10" in a.values("src_ip") or "203.0.113.99" in a.values("src_ip") for a in result.alerts)


def test_windows_sample_end_to_end():
    text = open(os.path.join(ROOT, "samples", "windows_security.json")).read()
    result = analyze_text(text)
    assert rule_ids(result.alerts) == ["AS-001", "AS-002", "AS-003", "AS-004"]
    lock = next(a for a in result.alerts if a.rule_id == "AS-004")
    assert lock.values("workstation") == ["WS-114"]


@pytest.mark.parametrize("secs,text", [(5, "5s"), (91, "1m 31s"), (3720, "1h 02m")])
def test_fmt_span(secs, text):
    assert fmt_span(timedelta(seconds=secs)) == text
