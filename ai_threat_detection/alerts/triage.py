"""Analyst workflow. Feedback is recorded with actor/time/reason; it never changes
experiment ground truth and is never fed into training automatically."""

from __future__ import annotations

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from ai_threat_detection.core.audit import audit

from .models import Alert, Assessment, Suppression, TriageEvent, WorkflowStatus

ALLOWED = {
    "NEW": {"ACKNOWLEDGED", "INVESTIGATING", "CLOSED"},
    "ACKNOWLEDGED": {"INVESTIGATING", "CLOSED"},
    "INVESTIGATING": {"ACKNOWLEDGED", "CLOSED"},
    "CLOSED": {"INVESTIGATING"},
}
MAX_SUPPRESSION_DAYS = 30


class TriageError(ValueError):
    pass


def triage(alert: Alert, actor, to_status: str | None, to_assessment: str | None, note: str) -> TriageEvent:
    note = (note or "").strip()[:4000]
    to_status = to_status or alert.workflow_status
    to_assessment = to_assessment or alert.assessment
    if to_status not in WorkflowStatus.values or to_assessment not in Assessment.values:
        raise TriageError("invalid status/assessment")
    if to_status != alert.workflow_status and to_status not in ALLOWED[alert.workflow_status]:
        raise TriageError(f"transition {alert.workflow_status} -> {to_status} not allowed")
    if to_status == "CLOSED" and to_assessment == "NEEDS_REVIEW":
        raise TriageError("closing requires an assessment")
    if to_assessment != alert.assessment and len(note) < 5:
        raise TriageError("changing the assessment requires a note (>= 5 chars)")
    if to_status == alert.workflow_status and to_assessment == alert.assessment and not note:
        raise TriageError("nothing to record")
    with transaction.atomic():
        ev = TriageEvent.objects.create(
            alert=alert,
            actor=actor,
            actor_label=actor.get_username(),
            from_status=alert.workflow_status,
            to_status=to_status,
            from_assessment=alert.assessment,
            to_assessment=to_assessment,
            note=note,
        )
        Alert.objects.filter(pk=alert.pk).update(
            workflow_status=to_status, assessment=to_assessment, updated_at=timezone.now()
        )
        audit(
            actor, "alert.triage", "alert", alert.pk, note[:200], status=to_status, assessment=to_assessment
        )
    alert.refresh_from_db()
    return ev


def create_suppression(
    actor,
    *,
    domain: str,
    entity_key: str = "",
    rule_id: str = "",
    detection_source: str = "",
    reason: str,
    days: int,
) -> Suppression:
    if len((reason or "").strip()) < 10:
        raise TriageError("suppression requires a reason (>= 10 chars)")
    if not 1 <= days <= MAX_SUPPRESSION_DAYS:
        raise TriageError(f"expiry must be 1..{MAX_SUPPRESSION_DAYS} days")
    if not (entity_key or rule_id):
        raise TriageError("scope must include an entity or a rule (no domain-wide suppression)")
    s = Suppression.objects.create(
        domain=domain,
        entity_key=entity_key[:40],
        rule_id=rule_id[:16],
        detection_source=detection_source[:16],
        reason=reason.strip()[:500],
        expires_at=timezone.now() + timedelta(days=days),
        actor=actor,
    )
    audit(
        actor,
        "suppression.create",
        "suppression",
        s.pk,
        reason,
        domain=domain,
        entity=entity_key,
        rule=rule_id,
        days=days,
    )
    return s


def revoke_suppression(s: Suppression, actor) -> None:
    s.revoked_at = timezone.now()
    s.revoked_by = actor
    s.save(update_fields=["revoked_at", "revoked_by"])
    audit(actor, "suppression.revoke", "suppression", s.pk, "")
