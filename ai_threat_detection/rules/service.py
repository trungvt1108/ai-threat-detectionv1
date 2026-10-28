from __future__ import annotations

import json
from pathlib import Path

from django.db import transaction

from ai_threat_detection.core.audit import audit

from .engine import Rule, RuleValidationError, parse_rule
from .models import RuleConfig

DEFAULT_PACK = Path(__file__).with_name("default_rules.json")


def load_default_pack() -> dict:
    return json.loads(DEFAULT_PACK.read_text(encoding="utf-8"))


def ensure_default_rules() -> int:
    """Seed rule version 1 for rules that do not exist yet. Never overwrites edits."""
    pack = load_default_pack()
    created = 0
    for d in pack["rules"]:
        rule = parse_rule(d, version=1)
        if not RuleConfig.objects.filter(rule_id=rule.rule_id).exists():
            RuleConfig.objects.create(
                rule_id=rule.rule_id,
                version=1,
                domain=rule.domain,
                definition={**d, "version": 1},
                reason=f"seed from {pack['pack']} {pack['pack_version']}",
            )
            created += 1
    return created


def current_rules(domain: str | None = None, include_disabled: bool = False) -> list[Rule]:
    qs = RuleConfig.objects.filter(is_current=True)
    if domain:
        qs = qs.filter(domain=domain)
    if not include_disabled:
        qs = qs.filter(enabled=True)
    return [parse_rule(rc.definition, version=rc.version) for rc in qs.order_by("rule_id")]


def rule_versions_snapshot() -> dict[str, int]:
    return {rc.rule_id: rc.version for rc in RuleConfig.objects.filter(is_current=True, enabled=True)}


def update_rule(rule_id: str, new_definition: dict, enabled: bool, actor, reason: str) -> RuleConfig:
    if not reason or len(reason.strip()) < 5:
        raise RuleValidationError("a reason (>= 5 chars) is required for rule changes")
    with transaction.atomic():
        cur = RuleConfig.objects.select_for_update().get(rule_id=rule_id, is_current=True)
        if new_definition.get("rule_id") != rule_id:
            raise RuleValidationError("rule_id cannot change")
        if new_definition.get("domain") != cur.domain:
            raise RuleValidationError("domain cannot change")
        version = cur.version + 1
        parse_rule(new_definition, version=version)
        cur.is_current = False
        cur.save(update_fields=["is_current"])
        rc = RuleConfig.objects.create(
            rule_id=rule_id,
            version=version,
            domain=cur.domain,
            definition={**new_definition, "version": version},
            enabled=enabled,
            is_current=True,
            actor=actor if getattr(actor, "is_authenticated", False) else None,
            actor_label=actor.get_username()
            if getattr(actor, "is_authenticated", False)
            else str(actor or "system"),
            reason=reason.strip()[:500],
        )
        audit(
            actor,
            "rule.update",
            "rule",
            rule_id,
            reason,
            from_version=cur.version,
            to_version=version,
            enabled=enabled,
        )
    return rc
