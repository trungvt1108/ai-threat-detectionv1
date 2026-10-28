"""Small declarative rule engine.

A rule is data, not code: a list of conditions ``{feature, op, value}`` combined
with AND. Features must come from the domain's computed-feature allowlist and
operators from a fixed set; no expressions, Python, shell or regex are accepted.
A rule whose features are missing (None) returns NOT_EVALUABLE, never "benign".
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass, field
from typing import Any

from ai_threat_detection.features.spec import COMPUTED_FEATURES

HEALTH_METRICS = (
    "parse_failure_ratio",
    "records_total",
    "rejected",
    "stale_ratio",
    "gap_over_expected_ratio",
    "late_events",
    "future_events",
)

ALLOWED_FEATURES: dict[str, tuple[str, ...]] = {**COMPUTED_FEATURES, "HEALTH": HEALTH_METRICS}
OPS = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "==": operator.eq}
SEVERITIES = ("info", "low", "medium", "high")
CATEGORIES = ("threat", "operational", "health")
RULE_ID_RE = re.compile(r"^[A-Z]{2,8}-\d{3}$")


class RuleValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Condition:
    feature: str
    op: str
    value: float


@dataclass(frozen=True)
class Rule:
    rule_id: str
    version: int
    domain: str
    name: str
    severity: str
    conditions: tuple[Condition, ...]
    description: str = ""
    limitation: str = ""
    review_hint: str = ""
    attack_mapping: dict[str, str] = field(default_factory=dict)
    category: str = "threat"


@dataclass
class RuleResult:
    rule_id: str
    version: int
    status: str  # TRIGGERED | NOT_TRIGGERED | NOT_EVALUABLE
    observed: dict[str, Any]
    thresholds: list[dict[str, Any]]
    missing: list[str]
    severity: str
    name: str
    limitation: str
    category: str = "threat"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "status": self.status,
            "observed": self.observed,
            "thresholds": self.thresholds,
            "missing": self.missing,
            "severity": self.severity,
            "name": self.name,
            "limitation": self.limitation,
            "category": self.category,
        }


def parse_rule(d: dict[str, Any], version: int | None = None) -> Rule:
    if not isinstance(d, dict):
        raise RuleValidationError("rule must be an object")
    allowed_keys = {
        "rule_id",
        "version",
        "domain",
        "name",
        "severity",
        "conditions",
        "description",
        "limitation",
        "review_hint",
        "attack_mapping",
        "category",
    }
    extra = set(d) - allowed_keys
    if extra:
        raise RuleValidationError(f"unknown rule keys: {sorted(extra)}")
    rid = d.get("rule_id")
    if not isinstance(rid, str) or not RULE_ID_RE.match(rid):
        raise RuleValidationError("rule_id must look like ABC-001")
    domain = d.get("domain")
    if domain not in ALLOWED_FEATURES:
        raise RuleValidationError(f"domain must be one of {sorted(ALLOWED_FEATURES)}")
    sev = d.get("severity", "low")
    if sev not in SEVERITIES:
        raise RuleValidationError(f"severity must be one of {SEVERITIES}")
    conds_raw = d.get("conditions")
    if not isinstance(conds_raw, list) or not 1 <= len(conds_raw) <= 8:
        raise RuleValidationError("1..8 conditions required")
    conds = []
    for c in conds_raw:
        if not isinstance(c, dict) or set(c) - {"feature", "op", "value"}:
            raise RuleValidationError("condition must be {feature, op, value}")
        feat, op, val = c.get("feature"), c.get("op"), c.get("value")
        if feat not in ALLOWED_FEATURES[domain]:
            raise RuleValidationError(f"feature {feat!r} not allowed for domain {domain}")
        if op not in OPS:
            raise RuleValidationError(f"op {op!r} not allowed")
        if isinstance(val, bool) or not isinstance(val, int | float) or not (-1e12 <= float(val) <= 1e12):
            raise RuleValidationError("value must be a bounded number")
        conds.append(Condition(feat, op, float(val)))
    category = d.get("category", "threat")
    if category not in CATEGORIES:
        raise RuleValidationError(f"category must be one of {CATEGORIES}")
    if domain == "HEALTH":
        category = "health"
    mapping = d.get("attack_mapping") or {}
    if not isinstance(mapping, dict) or not all(isinstance(v, str) for v in mapping.values()):
        raise RuleValidationError("attack_mapping must be a string map")
    ver = version if version is not None else int(d.get("version", 1))
    return Rule(
        rule_id=rid,
        version=ver,
        domain=domain,
        name=str(d.get("name", rid))[:120],
        severity=sev,
        conditions=tuple(conds),
        description=str(d.get("description", ""))[:1000],
        limitation=str(d.get("limitation", ""))[:1000],
        review_hint=str(d.get("review_hint", ""))[:1000],
        attack_mapping={str(k)[:40]: v[:200] for k, v in mapping.items()},
        category=category,
    )


def evaluate(rule: Rule, values: dict[str, Any]) -> RuleResult:
    observed: dict[str, Any] = {}
    missing: list[str] = []
    hits = []
    for c in rule.conditions:
        v = values.get(c.feature)
        observed[c.feature] = v
        if v is None:
            missing.append(c.feature)
            continue
        hits.append(OPS[c.op](float(v), c.value))
    if missing:
        status = "NOT_EVALUABLE"
    else:
        status = "TRIGGERED" if all(hits) else "NOT_TRIGGERED"
    return RuleResult(
        rule_id=rule.rule_id,
        version=rule.version,
        status=status,
        observed=observed,
        thresholds=[{"feature": c.feature, "op": c.op, "value": c.value} for c in rule.conditions],
        missing=missing,
        severity=rule.severity,
        name=rule.name,
        limitation=rule.limitation,
        category=rule.category,
    )


def evaluate_all(rules: list[Rule], domain: str, values: dict[str, Any]) -> list[RuleResult]:
    return [evaluate(r, values) for r in rules if r.domain == domain]
