"""Load and validate YAML detection rules."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional

import yaml

from .models import GROUP_FIELDS, OUTCOMES, SEVERITIES

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "default.yaml")
RULE_TYPES = ("threshold", "distinct", "sequence")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    type: str
    severity: str
    group_by: tuple
    threshold: int
    window: timedelta
    attack: Dict[str, str]
    description: str = ""
    outcome: str = "failure"
    distinct_field: str = ""
    response: tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class RuleSet:
    rules: List[Rule]
    escalation: Dict[str, str]


def _rule(d: dict) -> Rule:
    where = f"rule {d.get('id', '?')}"
    for k in ("id", "name", "type", "severity", "group_by", "threshold", "window_minutes", "attack"):
        if k not in d:
            raise ValueError(f"{where}: missing '{k}'")
    if d["type"] not in RULE_TYPES:
        raise ValueError(f"{where}: type must be one of {RULE_TYPES}")
    if d["severity"] not in SEVERITIES:
        raise ValueError(f"{where}: severity must be one of {SEVERITIES}")
    group_by = tuple(d["group_by"])
    bad = [g for g in group_by if g not in GROUP_FIELDS]
    if bad or not group_by:
        raise ValueError(f"{where}: group_by fields must be from {GROUP_FIELDS}")
    outcome = d.get("outcome", "failure")
    if outcome not in OUTCOMES:
        raise ValueError(f"{where}: outcome must be one of {OUTCOMES}")
    if int(d["threshold"]) < 1 or float(d["window_minutes"]) <= 0:
        raise ValueError(f"{where}: threshold and window_minutes must be positive")
    distinct = d.get("distinct_field", "")
    if d["type"] == "distinct" and distinct not in GROUP_FIELDS:
        raise ValueError(f"{where}: distinct rules need distinct_field from {GROUP_FIELDS}")
    attack = d["attack"]
    if not isinstance(attack, dict) or not str(attack.get("technique", "")).startswith("T"):
        raise ValueError(f"{where}: attack.technique must be a MITRE ATT&CK ID like T1110")
    return Rule(id=str(d["id"]), name=d["name"], type=d["type"], severity=d["severity"],
                group_by=group_by, threshold=int(d["threshold"]),
                window=timedelta(minutes=float(d["window_minutes"])),
                attack={k: str(v) for k, v in attack.items()}, description=d.get("description", ""),
                outcome=outcome, distinct_field=distinct, response=tuple(d.get("response", [])))


def load_rules(path: Optional[str] = None) -> RuleSet:
    with open(path or DEFAULT_RULES, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    rules = [_rule(r) for r in data.get("rules", [])]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("rule ids must be unique")
    if not rules:
        raise ValueError("no rules defined")
    return RuleSet(rules=rules, escalation=dict(data.get("escalation", {})))
