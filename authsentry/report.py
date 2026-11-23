"""Incident reports in JSON (for tools) and Markdown (for people)."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List

from .engine import fmt_span
from .models import Alert, ParseResult, SEVERITIES

EVIDENCE_LINES = 10


@dataclass
class Analysis:
    parsed: ParseResult
    alerts: List[Alert]
    escalation: Dict[str, str]


def attack_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def summary(a: Analysis) -> dict:
    ev = a.parsed.events
    failures = Counter(e.src_ip or "(none)" for e in ev if e.outcome == "failure")
    return {
        "format": a.parsed.format,
        "records_total": a.parsed.records_total,
        "records_ignored": a.parsed.records_ignored,
        "events": len(ev),
        "by_outcome": dict(Counter(e.outcome for e in ev)),
        "unique_sources": len({e.src_ip for e in ev if e.src_ip}),
        "unique_users": len({e.user for e in ev if e.user}),
        "first_event": ev[0].timestamp.isoformat() if ev else None,
        "last_event": ev[-1].timestamp.isoformat() if ev else None,
        "alerts": len(a.alerts),
        "alerts_by_severity": {s: sum(1 for x in a.alerts if x.severity == s) for s in reversed(SEVERITIES)},
        "top_failing_sources": [{"src_ip": ip, "failures": n} for ip, n in failures.most_common(5)],
        "warnings": a.parsed.warnings,
    }


def alert_dict(x: Alert, escalation: Dict[str, str]) -> dict:
    return {
        "incident_id": x.incident_id,
        "rule_id": x.rule_id,
        "rule_name": x.rule_name,
        "severity": x.severity,
        "attack": dict(x.attack, url=attack_url(x.attack["technique"])),
        "group": dict(x.group),
        "detail": x.detail,
        "first_seen": x.first_seen.isoformat(),
        "last_seen": x.last_seen.isoformat(),
        "duration": fmt_span(x.span),
        "event_count": len(x.events),
        "src_ips": x.values("src_ip"),
        "users": x.values("user"),
        "hosts": x.values("host"),
        "workstations": x.values("workstation"),
        "evidence": [{"line": e.line_no, "raw": e.raw} for e in x.events[:EVIDENCE_LINES]],
        "evidence_omitted": max(0, len(x.events) - EVIDENCE_LINES),
        "triage": x.response,
        "escalation": escalation.get(x.severity, ""),
    }


def to_dict(a: Analysis) -> dict:
    return {"summary": summary(a), "alerts": [alert_dict(x, a.escalation) for x in a.alerts]}


def ts(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat(sep=" ")


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(a: Analysis, generated: datetime = None) -> str:
    s = summary(a)
    generated = generated or datetime.now(timezone.utc).replace(microsecond=0)
    out = ["# AuthSentry incident report", "",
           f"Generated {generated.isoformat()} · input: {s['format']} · "
           f"{s['events']} auth events from {s['records_total']} records ({s['records_ignored']} ignored)", ""]
    for w in s["warnings"]:
        out += [f"> Warning: {w}", ""]
    out += ["## Summary", "",
            "| Severity | Alerts |", "|---|---|"]
    out += [f"| {sev} | {n} |" for sev, n in s["alerts_by_severity"].items()]
    out += ["", f"Outcomes: " + (", ".join(f"{k} {v}" for k, v in s["by_outcome"].items()) or "none") +
            f" · unique sources: {s['unique_sources']} · unique accounts: {s['unique_users']}", ""]
    if not a.alerts:
        out += ["No rule fired. Nothing to escalate.", ""]
        return "\n".join(out)
    out += ["| Incident | Severity | Rule | ATT&CK | Source(s) | Account(s) | Events | First seen | Last seen |",
            "|---|---|---|---|---|---|---|---|---|"]
    for x in a.alerts:
        out.append("| " + " | ".join(_cell(c) for c in [
            x.incident_id, x.severity.upper(), f"{x.rule_id} {x.rule_name}", x.attack["technique"],
            ", ".join(x.values("src_ip")) or "-", ", ".join(x.values("user")) or "-", len(x.events),
            ts(x.first_seen), ts(x.last_seen)]) + " |")
    out.append("")
    for x in a.alerts:
        out += [f"## {x.incident_id} · {x.severity.upper()} · {x.rule_name}", "",
                f"- **Rule:** {x.rule_id}",
                f"- **MITRE ATT&CK:** {x.attack['technique']} {x.attack.get('name', '')} "
                f"({x.attack.get('tactic', '')}) — {attack_url(x.attack['technique'])}",
                f"- **What happened:** {x.detail}",
                f"- **Window:** {ts(x.first_seen)} → {ts(x.last_seen)} ({fmt_span(x.span)})",
                f"- **Hosts:** {', '.join(x.values('host')) or '-'}"]
        if x.values("workstation"):
            out.append(f"- **Workstations:** {', '.join(x.values('workstation'))}")
        out += ["", f"### Evidence ({min(len(x.events), EVIDENCE_LINES)} of {len(x.events)} events)", "", "~~~text"]
        out += [f"{e.line_no:>5}: {e.raw.replace('~~~', '~ ~ ~')}" for e in x.events[:EVIDENCE_LINES]]
        out += ["~~~", "", "### Triage"]
        out += [f"{i}. {step}" for i, step in enumerate(x.response, 1)]
        out += ["", f"### Escalation", "", a.escalation.get(x.severity, "Follow the team's escalation policy."), ""]
    return "\n".join(out)
