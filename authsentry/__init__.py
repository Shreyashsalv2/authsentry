"""AuthSentry: a small SOC detection lab for authentication logs.

    from authsentry import analyze_text
    result = analyze_text(open("auth.log").read(), year=2026)
    print(to_markdown(result))
"""
from typing import Optional

from .engine import detect
from .parsers import parse
from .report import Analysis, to_dict, to_markdown
from .rules import RuleSet, load_rules

__all__ = ["analyze_text", "to_dict", "to_markdown", "load_rules", "Analysis"]
__version__ = "0.1.0"


def analyze_text(text: str, fmt: str = "auto", year: Optional[int] = None,
                 ruleset: Optional[RuleSet] = None) -> Analysis:
    ruleset = ruleset or load_rules()
    parsed = parse(text, fmt=fmt, year=year)
    return Analysis(parsed=parsed, alerts=detect(parsed.events, ruleset), escalation=ruleset.escalation)
