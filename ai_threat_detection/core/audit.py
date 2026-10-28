from __future__ import annotations

from typing import Any

from ai_threat_detection.normalization.privacy import scrub_text

from .models import AuditLog


def _clean(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        return {str(k)[:64]: _clean(v, depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, list | tuple):
        return [_clean(v, depth + 1) for v in list(value)[:50]]
    if isinstance(value, str):
        return scrub_text(value, max_len=500)[0]
    if value is None or isinstance(value, bool | int | float):
        return value
    return scrub_text(str(value), max_len=200)[0]


def audit(
    actor, action: str, object_type: str, object_id: Any = "", reason: str = "", **details: Any
) -> AuditLog:
    label = "system"
    user = None
    if actor is not None and getattr(actor, "is_authenticated", False):
        user = actor
        label = actor.get_username()
    elif isinstance(actor, str):
        label = actor[:150]
    return AuditLog.objects.create(
        actor=user,
        actor_label=label,
        action=action,
        object_type=object_type,
        object_id=str(object_id)[:128],
        reason=scrub_text(reason or "", max_len=1000)[0],
        details=_clean(details),
    )
