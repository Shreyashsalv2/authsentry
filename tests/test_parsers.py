import json
from datetime import datetime

import pytest

from authsentry.parsers import detect_format, parse, parse_linux_auth, parse_timestamp, parse_windows_events


def test_failed_and_accepted_sshd_lines():
    text = (
        "Nov 23 09:00:01 web01 sshd[805]: Failed password for root from 203.0.113.45 port 41200 ssh2\n"
        "Nov 23 09:00:02 web01 sshd[806]: Accepted publickey for alice from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:x\n"
    )
    r = parse_linux_auth(text, year=2026)
    assert [(e.outcome, e.user, e.src_ip, e.method) for e in r.events] == [
        ("failure", "root", "203.0.113.45", "password"),
        ("success", "alice", "192.0.2.10", "publickey"),
    ]
    assert r.events[0].timestamp == datetime(2026, 11, 23, 9, 0, 1)
    assert r.events[0].line_no == 1 and r.events[0].host == "web01"


def test_invalid_user_is_parsed_without_prefix():
    r = parse_linux_auth("Nov 23 09:03:00 web01 sshd[822]: Failed password for invalid user admin from 198.51.100.23 port 52000 ssh2", 2026)
    assert r.events[0].user == "admin"


def test_pam_duplicates_and_noise_are_ignored():
    text = (
        "Nov 23 09:00:01 web01 sshd[804]: pam_unix(sshd:auth): authentication failure; rhost=203.0.113.45  user=root\n"
        "Nov 23 09:00:01 web01 sshd[805]: Failed password for root from 203.0.113.45 port 41200 ssh2\n"
        "Nov 23 09:00:02 web01 CRON[900]: pam_unix(cron:session): session opened for user root\n"
        "Nov 23 09:00:03 web01 sshd[807]: Invalid user test from 198.51.100.23 port 4242\n"
        "garbage line\n"
    )
    r = parse_linux_auth(text, 2026)
    assert len(r.events) == 1
    assert r.records_total == 5 and r.records_ignored == 4


def test_rfc3339_timestamps_and_sshd_session_process():
    r = parse_linux_auth("2026-11-23T14:30:01.123456+05:30 web01 sshd-session[42]: Failed password for root from 2001:db8::7 port 22 ssh2")
    e = r.events[0]
    assert e.timestamp == datetime(2026, 11, 23, 9, 0, 1, 123456)  # converted to UTC
    assert e.src_ip == "2001:db8::7"


def test_year_rolls_over_from_december_to_january():
    text = ("Dec 31 23:59:58 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n"
            "Jan  1 00:00:02 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2\n")
    r = parse_linux_auth(text, 2025)
    assert [e.timestamp.year for e in r.events] == [2025, 2026]


def test_warning_when_no_sshd_lines():
    r = parse_linux_auth("Nov 23 09:00:02 web01 CRON[900]: hello\n", 2026)
    assert r.events == [] and r.warnings


def test_windows_flat_json_array():
    recs = [
        {"TimeCreated": "2026-11-23T10:02:00.5112340Z", "Id": 4625, "MachineName": "DC01", "TargetUserName": "Administrator",
         "IpAddress": "203.0.113.77", "LogonType": 10, "WorkstationName": "KALI"},
        {"TimeCreated": "2026-11-23T10:05:00Z", "Id": 4740, "MachineName": "DC01", "TargetUserName": "jsmith",
         "CallerComputerName": "WS-114"},
        {"TimeCreated": "2026-11-23T10:06:00Z", "Id": 4672, "MachineName": "DC01"},
    ]
    r = parse_windows_events(json.dumps(recs))
    assert [(e.event_id, e.outcome, e.user) for e in r.events] == [(4625, "failure", "Administrator"), (4740, "lockout", "jsmith")]
    assert r.events[0].method == "logon type 10" and r.events[0].timestamp.microsecond == 511234
    assert r.events[1].workstation == "WS-114" and r.events[1].src_ip == ""
    assert r.records_ignored == 1


def test_windows_nested_evtx_json_lines():
    rec = {"Event": {"System": {"EventID": {"#text": 4624, "#attributes": {"Qualifiers": ""}},
                                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-23T10:00:00.000000Z"}},
                                "Computer": "DC01.corp.example"},
                     "EventData": {"TargetUserName": "jdoe", "IpAddress": "10.0.0.15", "LogonType": 3}}}
    r = parse_windows_events(json.dumps(rec) + "\nnot json\n")
    assert len(r.events) == 1
    e = r.events[0]
    assert (e.outcome, e.user, e.src_ip, e.host) == ("success", "jdoe", "10.0.0.15", "DC01.corp.example")
    assert r.records_ignored == 1


def test_windows_data_name_list_and_dash_ip():
    rec = {"System": {"EventID": 4625, "TimeCreated": "2026-11-23T10:00:00Z", "Computer": "SRV1"},
           "EventData": {"Data": [{"Name": "TargetUserName", "#text": "bob"}, {"Name": "IpAddress", "#text": "-"}]}}
    e = parse_windows_events(json.dumps([rec])).events[0]
    assert e.user == "bob" and e.src_ip == ""


def test_powershell_date_format():
    assert parse_timestamp("/Date(1795420800000)/") == datetime(2026, 11, 23, 8, 0, 0)


def test_detect_format_and_unknown_format():
    assert detect_format('  [{"Id": 4625}]') == "windows"
    assert detect_format("Nov 23 09:00:01 web01 sshd[1]: x") == "linux"
    with pytest.raises(ValueError):
        parse("x", fmt="splunk")
