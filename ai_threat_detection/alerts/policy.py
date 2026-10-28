"""Alert severity / combination policy v1 (documented in docs/ARCHITECTURE.md).

* RULE only        -> the highest severity among triggered rules.
* ML_ANOMALY only  -> low (anomaly score above validated threshold; needs review).
* RULE_AND_ML      -> rule severity raised one level (max high).
* UPSTREAM_IDS     -> Suricata severity 1 -> high, 2 -> medium, otherwise low
                      (that is the upstream sensor's rating, shown as such).
* DATA_QUALITY     -> low.
Combination: an alert is raised if any rule TRIGGERED or the ML decision is
SCORED with score >= threshold (logical OR). NOT_EVALUABLE / INSUFFICIENT_DATA
never raise alerts and never count as benign evidence.
Grouping: same namespace + domain + entity; a new decision within COOLDOWN of an
open (not CLOSED) alert's end is attached to it as additional evidence.
"""

from __future__ import annotations

from datetime import timedelta

POLICY_VERSION = "alert-policy-v1"
COOLDOWN = timedelta(minutes=15)
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def max_severity(*sevs: str) -> str:
    valid = [s for s in sevs if s in SEVERITY_ORDER]
    return max(valid, key=SEVERITY_ORDER.__getitem__) if valid else "low"


def bump(sev: str) -> str:
    order = list(SEVERITY_ORDER)
    return order[min(SEVERITY_ORDER.get(sev, 1) + 1, len(order) - 1)]


def combine_source(rule_hit: bool, ml_hit: bool) -> str | None:
    if rule_hit and ml_hit:
        return "RULE_AND_ML"
    if rule_hit:
        return "RULE"
    if ml_hit:
        return "ML_ANOMALY"
    return None


def merge_sources(a: str, b: str) -> str:
    if a == b:
        return a
    parts = set()
    for s in (a, b):
        if s == "RULE_AND_ML":
            parts |= {"RULE", "ML_ANOMALY"}
        else:
            parts.add(s)
    if parts == {"RULE", "ML_ANOMALY"}:
        return "RULE_AND_ML"
    return a


def severity_for(source: str, rule_severities: list[str], upstream_severity: int | None = None) -> str:
    if source == "RULE":
        return max_severity(*rule_severities)
    if source == "ML_ANOMALY":
        return "low"
    if source == "RULE_AND_ML":
        return bump(max_severity(*rule_severities))
    if source == "UPSTREAM_IDS":
        return {1: "high", 2: "medium"}.get(upstream_severity or 0, "low")
    return "low"
