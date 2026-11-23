"""Turn raw logs into AuthEvent records.

Supported inputs
- Linux OpenSSH logs (/var/log/auth.log, /var/log/secure, journald export) in classic
  syslog form ("Nov 23 09:00:01 web01 sshd[812]: ...") or RFC 3339 form
  ("2026-11-23T09:00:01.123+05:30 web01 sshd[812]: ...").
- Windows Security events 4624 (logon), 4625 (failed logon) and 4740 (account locked out),
  exported as a JSON array or JSON lines. Flat exports (Get-WinEvent | Select-Object ...)
  and nested EVTX-to-JSON exports (System / EventData) both work.

Only sshd's own "Failed ..." and "Accepted ..." lines are counted. PAM's duplicate
"authentication failure" lines are ignored so one attempt is never counted twice.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .models import AuthEvent, ParseResult

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SYSLOG_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.*)$")
SSHD_PREFIX = re.compile(r"^sshd(?:-session)?(?:\[\d+\])?:\s+(?P<msg>.*)$")
IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*?) from " + IP + r" port \d+")
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.*?) from " + IP + r" port \d+")

WINDOWS_OUTCOME = {4624: "success", 4625: "failure", 4740: "lockout"}
EMPTY = {"", "-", "null", "None"}


def parse_timestamp(value: Any) -> datetime:
    """Parse ISO 8601 (any number of fraction digits) or PowerShell's /Date(ms)/ into naive UTC."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc).replace(tzinfo=None)
    s = str(value).strip()
    m = re.fullmatch(r"/Date\((-?\d+)\)/", s)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc).replace(tzinfo=None)
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?", s)
    if not m:
        raise ValueError(f"unrecognised timestamp: {s!r}")
    date, clock, frac, tz = m.groups()
    text = f"{date}T{clock}" + (f".{(frac + '000000')[:6]}" if frac else "")
    if tz and tz != "Z":
        text += tz if ":" in tz else f"{tz[:3]}:{tz[3:]}"
    elif tz == "Z":
        text += "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def parse_linux_auth(text: str, year: Optional[int] = None) -> ParseResult:
    """Parse OpenSSH lines. Classic syslog has no year, so pass `year` (defaults to this year).
    A Dec -> Jan jump inside one file moves to the next year."""
    year = int(year) if year else datetime.now().year
    events: List[AuthEvent] = []
    total = ignored = 0
    prev_month = 0
    warnings: List[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        total += 1
        iso = ISO_LINE.match(line)
        if iso:
            try:
                ts = parse_timestamp(iso["ts"])
            except ValueError:
                ignored += 1
                continue
            host, rest = iso["host"], iso["rest"]
        else:
            sl = SYSLOG_LINE.match(line)
            if not sl or sl["mon"] not in MONTHS:
                ignored += 1
                continue
            month = MONTHS[sl["mon"]]
            if prev_month and month < prev_month and prev_month - month > 6:
                year += 1
            prev_month = month
            hh, mm, ss = (int(x) for x in sl["time"].split(":"))
            try:
                ts = datetime(year, month, int(sl["day"]), hh, mm, ss)
            except ValueError:
                ignored += 1
                continue
            host, rest = sl["host"], sl["rest"]
        sshd = SSHD_PREFIX.match(rest)
        if not sshd:
            ignored += 1
            continue
        msg = sshd["msg"]
        m = FAILED.match(msg)
        outcome = "failure"
        if not m:
            m = ACCEPTED.match(msg)
            outcome = "success"
        if not m:
            ignored += 1
            continue
        events.append(AuthEvent(timestamp=ts, source="linux-sshd", host=host, outcome=outcome,
                                user=m["user"], src_ip=m["ip"], method=m["method"],
                                line_no=n, raw=line))
    if total and not events:
        warnings.append("No sshd Failed/Accepted lines found. Is this an auth.log or secure file?")
    return ParseResult("linux-sshd", sorted(events, key=lambda e: (e.timestamp, e.line_no)), total, ignored, warnings)


def _flatten(obj: Any, out: Dict[str, Any]) -> Dict[str, Any]:
    """Collect leaf values by key name from nested exports. Top-level keys win."""
    if isinstance(obj, dict):
        later = []
        for k, v in obj.items():
            if isinstance(v, dict) and set(v) & {"#text", "Value", "value"} and not set(v) - {"#text", "#attributes", "Value", "value"}:
                v = v.get("#text", v.get("Value", v.get("value")))
            if isinstance(v, (dict, list)):
                later.append(v)
            elif k not in out:
                out[k] = v
        for v in later:
            _flatten(v, out)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, dict) and "Name" in v and ("#text" in v or "Value" in v):
                out.setdefault(v["Name"], v.get("#text", v.get("Value")))
            else:
                _flatten(v, out)
    return out


def _pick(rec: Dict[str, Any], *names: str) -> str:
    lower = {k.lower(): v for k, v in rec.items()}
    for n in names:
        v = lower.get(n.lower())
        if v is not None and str(v).strip() not in EMPTY:
            return str(v).strip()
    return ""


def _load_records(text: str) -> Iterable[tuple]:
    stripped = text.strip()
    if stripped.startswith("["):
        data = json.loads(stripped)
        if not isinstance(data, list):
            raise ValueError("expected a JSON array of events")
        for i, rec in enumerate(data, 1):
            yield i, rec, json.dumps(rec, separators=(",", ":"))
        return
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                yield i, json.loads(line), line.strip()
            except json.JSONDecodeError:
                yield i, None, line.strip()


def parse_windows_events(text: str) -> ParseResult:
    events: List[AuthEvent] = []
    total = ignored = 0
    for n, rec, raw in _load_records(text):
        total += 1
        if not isinstance(rec, dict):
            ignored += 1
            continue
        flat = _flatten(rec, {})
        try:
            event_id = int(_pick(flat, "EventID", "Id", "EventId", "event_id") or 0)
        except ValueError:
            event_id = 0
        outcome = WINDOWS_OUTCOME.get(event_id)
        when = _pick(flat, "TimeCreated", "SystemTime", "TimeGenerated", "@timestamp", "timestamp")
        if not outcome or not when:
            ignored += 1
            continue
        try:
            ts = parse_timestamp(when)
        except ValueError:
            ignored += 1
            continue
        logon_type = _pick(flat, "LogonType")
        events.append(AuthEvent(
            timestamp=ts, source="windows-security",
            host=_pick(flat, "Computer", "MachineName", "Hostname", "host"),
            outcome=outcome, user=_pick(flat, "TargetUserName", "user"),
            src_ip=_pick(flat, "IpAddress", "src_ip"),
            method=f"logon type {logon_type}" if logon_type else "",
            workstation=_pick(flat, "CallerComputerName", "WorkstationName", "Workstation"),
            event_id=event_id, line_no=n, raw=raw))
    warnings = [] if events or not total else ["No 4624/4625/4740 events found in the JSON."]
    return ParseResult("windows-security", sorted(events, key=lambda e: (e.timestamp, e.line_no)), total, ignored, warnings)


def detect_format(text: str) -> str:
    return "windows" if text.lstrip()[:1] in ("[", "{") else "linux"


def parse(text: str, fmt: str = "auto", year: Optional[int] = None) -> ParseResult:
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt in ("linux", "linux-sshd", "sshd"):
        return parse_linux_auth(text, year)
    if fmt in ("windows", "windows-security", "json"):
        return parse_windows_events(text)
    raise ValueError(f"unknown format {fmt!r} (use auto, linux or windows)")
