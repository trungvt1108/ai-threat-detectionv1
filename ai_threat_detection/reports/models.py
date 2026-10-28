from __future__ import annotations

from django.conf import settings
from django.db import models


class Report(models.Model):
    report_id = models.CharField(max_length=64, unique=True)
    kind = models.CharField(max_length=24)
    params = models.JSONField(default=dict)
    public_draft = models.BooleanField(default=False)
    files = models.JSONField(default=dict)  # format -> {"rel": ..., "sha256": ...}
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
