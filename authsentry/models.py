"""Data types shared by the parsers, the detection engine and the reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

OUTCOMES = ("success", "failure", "lockout")
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
GROUP_FIELDS = ("src_ip", "user", "host", "source", "workstation")


@dataclass(frozen=True)
class AuthEvent:
    """One normalised authentication event, whatever log it came from."""

    timestamp: datetime
    source: str            # "linux-sshd" | "windows-security"
    host: str
    outcome: str           # "success" | "failure" | "lockout"
    user: str
    src_ip: str = ""
    method: str = ""       # sshd auth method, or "logon type N" on Windows
    workstation: str = ""  # Windows WorkstationName / CallerComputerName
    event_id: int = 0      # Windows event ID (0 for sshd)
    line_no: int = 0       # line (or record) number in the input
    raw: str = ""          # original line, kept as evidence


@dataclass
class ParseResult:
    format: str
    events: List[AuthEvent]
    records_total: int
    records_ignored: int
    warnings: List[str] = field(default_factory=list)


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    attack: Dict[str, str]
    group: Tuple[Tuple[str, str], ...]
    events: List[AuthEvent]
    detail: str
    response: List[str]
    incident_id: str = ""

    @property
    def first_seen(self) -> datetime:
        return self.events[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def span(self) -> timedelta:
        return self.last_seen - self.first_seen

    def values(self, name: str) -> List[str]:
        """Distinct non-empty values of one event field, in first-seen order."""
        seen: List[str] = []
        for e in self.events:
            v = getattr(e, name)
            if v and v not in seen:
                seen.append(v)
        return seen
