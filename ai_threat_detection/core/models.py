from __future__ import annotations

from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """Append-only record of security-relevant changes (sources, privacy config,
    rules, thresholds, models, suppressions, triage, exports, user roles)."""

    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    actor_label = models.CharField(max_length=150, default="system")
    action = models.CharField(max_length=64, db_index=True)
    object_type = models.CharField(max_length=64)
    object_id = models.CharField(max_length=128, blank=True, default="")
    reason = models.TextField(blank=True, default="")
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.actor_label} {self.action} {self.object_type}:{self.object_id}"
