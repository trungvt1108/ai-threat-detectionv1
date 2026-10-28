from __future__ import annotations

from django.conf import settings
from django.db import models


class Job(models.Model):
    STATUSES = [
        ("QUEUED", "Queued"),
        ("RUNNING", "Running"),
        ("CANCEL_REQUESTED", "Cancel requested"),
        ("SUCCEEDED", "Succeeded"),
        ("FAILED", "Failed"),
        ("CANCELLED", "Cancelled"),
        ("TIMED_OUT", "Timed out"),
    ]
    kind = models.CharField(max_length=32)
    params = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=STATUSES, default="QUEUED", db_index=True)
    lock_key = models.CharField(max_length=120, blank=True, default="")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_by_label = models.CharField(max_length=150, default="system")
    worker_id = models.CharField(max_length=80, blank=True, default="")
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=1)
    timeout_seconds = models.PositiveIntegerField(default=3600)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    progress = models.JSONField(default=dict)
    result = models.JSONField(default=dict)
    error = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    @property
    def is_active(self) -> bool:
        return self.status in {"QUEUED", "RUNNING", "CANCEL_REQUESTED"}
