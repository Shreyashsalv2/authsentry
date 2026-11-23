"""Run detection rules over normalised events and return alerts."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import timedelta
from typing import Dict, List, Sequence, Tuple

from .models import Alert, AuthEvent, SEVERITY_RANK
from .rules import Rule, RuleSet

LABEL = {"failure": "failed logins", "success": "successful logins", "lockout": "account lockouts"}
PLURAL = {"user": "accounts", "src_ip": "source IPs", "host": "hosts", "workstation": "workstations", "source": "log sources"}


def fmt_span(d: timedelta) -> str:
    s = int(d.total_seconds())
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def _group(events: Sequence[AuthEvent], keys: Sequence[str]) -> Dict[tuple, List[AuthEvent]]:
    groups: Dict[tuple, List[AuthEvent]] = defaultdict(list)
    for e in events:
        groups[tuple((k, getattr(e, k)) for k in keys)].append(e)
    return groups


def _describe(group: Tuple[Tuple[str, str], ...]) -> str:
    return ", ".join(f"{k}={v or '(none)'}" for k, v in group)


def _bursts(events: List[AuthEvent], rule: Rule) -> List[List[AuthEvent]]:
    """Sliding window over one group's events (sorted by time).

    The rule fires when `threshold` events (or distinct values) fall inside one window.
    The alert then stays open and absorbs every later event that comes within one window
    of the previous one, so a long attack is one incident, not dozens."""
    def measure(win) -> int:
        if rule.type == "distinct":
            return len({getattr(x, rule.distinct_field) for x in win})
        return len(win)

    bursts: List[List[AuthEvent]] = []
    window: deque = deque()
    current: List[AuthEvent] = []
    for e in events:
        if current:
            if e.timestamp - current[-1].timestamp <= rule.window:
                current.append(e)
                continue
            bursts.append(current)
            current = []
        window.append(e)
        while e.timestamp - window[0].timestamp > rule.window:
            window.popleft()
        if measure(window) >= rule.threshold:
            current = list(window)
            window.clear()
    if current:
        bursts.append(current)
    return bursts


def _threshold_alerts(events: Sequence[AuthEvent], rule: Rule) -> List[Alert]:
    alerts = []
    matching = [e for e in events if e.outcome == rule.outcome]
    for group, evs in _group(matching, rule.group_by).items():
        for burst in _bursts(evs, rule):
            span = fmt_span(burst[-1].timestamp - burst[0].timestamp)
            if rule.type == "distinct":
                vals = Counter(getattr(e, rule.distinct_field) for e in burst)
                detail = (f"{len(vals)} different {PLURAL[rule.distinct_field]} hit by {len(burst)} "
                          f"{LABEL[rule.outcome]} in {span} ({_describe(group)}).")
            else:
                detail = f"{len(burst)} {LABEL[rule.outcome]} in {span} ({_describe(group)})."
            alerts.append(Alert(rule.id, rule.name, rule.severity, rule.attack, group, burst,
                                detail, list(rule.response)))
    return alerts


def _sequence_alerts(events: Sequence[AuthEvent], rule: Rule) -> List[Alert]:
    alerts = []
    relevant = [e for e in events if e.outcome in ("failure", "success")]
    for group, evs in _group(relevant, rule.group_by).items():
        failures: deque = deque()
        for e in evs:
            if e.outcome == "failure":
                failures.append(e)
                continue
            while failures and e.timestamp - failures[0].timestamp > rule.window:
                failures.popleft()
            if len(failures) >= rule.threshold:
                users = sorted({f.user for f in failures})
                detail = (f"Login succeeded for '{e.user}' after {len(failures)} failed logins "
                          f"({', '.join(users)}) in {fmt_span(e.timestamp - failures[0].timestamp)} "
                          f"({_describe(group)}).")
                alerts.append(Alert(rule.id, rule.name, rule.severity, rule.attack, group,
                                    list(failures) + [e], detail, list(rule.response)))
                failures.clear()
    return alerts


def detect(events: Sequence[AuthEvent], ruleset: RuleSet) -> List[Alert]:
    events = sorted(events, key=lambda e: (e.timestamp, e.line_no))
    alerts: List[Alert] = []
    for rule in ruleset.rules:
        if rule.type == "sequence":
            alerts += _sequence_alerts(events, rule)
        else:
            alerts += _threshold_alerts(events, rule)
    alerts.sort(key=lambda a: (-SEVERITY_RANK[a.severity], a.first_seen, a.rule_id))
    for i, a in enumerate(alerts, 1):
        a.incident_id = f"INC-{i:04d}"
    return alerts
