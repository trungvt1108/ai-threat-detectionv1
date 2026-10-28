from __future__ import annotations

from django.conf import settings
from django.db import models


class DetectionSource(models.TextChoices):
    RULE = "RULE", "Rule"
    ML_ANOMALY = "ML_ANOMALY", "ML anomaly"
    RULE_AND_ML = "RULE_AND_ML", "Rule + ML"
    UPSTREAM_IDS = "UPSTREAM_IDS", "Upstream IDS"
    DATA_QUALITY = "DATA_QUALITY", "Data quality"


class WorkflowStatus(models.TextChoices):
    NEW = "NEW", "Mới"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Đã nhận"
    INVESTIGATING = "INVESTIGATING", "Đang điều tra"
    CLOSED = "CLOSED", "Đã đóng"


class Assessment(models.TextChoices):
    NEEDS_REVIEW = "NEEDS_REVIEW", "Cần review"
    TRUE_POSITIVE = "TRUE_POSITIVE", "True positive"
    FALSE_POSITIVE = "FALSE_POSITIVE", "False positive"
    EXPECTED_BEHAVIOR = "EXPECTED_BEHAVIOR", "Hành vi được phép"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE", "Cần thêm bằng chứng"


class Suppression(models.Model):
    """Scoped, expiring suppression. Suppressed alerts are still stored and visible."""

    domain = models.CharField(max_length=16)
    entity_key = models.CharField(max_length=40, blank=True, default="")
    rule_id = models.CharField(max_length=16, blank=True, default="")
    detection_source = models.CharField(max_length=16, blank=True, default="")
    reason = models.CharField(max_length=500)
    expires_at = models.DateTimeField()
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["-created_at"]


class Alert(models.Model):
    """A grouped alert (domain + entity + cooldown). Child decisions keep the raw
    per-window evidence. The number of alerts is not a number of attacks."""

    namespace = models.CharField(max_length=100, db_index=True)
    domain = models.CharField(max_length=16)
    entity_key = models.CharField(max_length=40, blank=True, default="")
    group_key = models.CharField(max_length=200, db_index=True)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    detection_source = models.CharField(max_length=16, choices=DetectionSource.choices)
    rule_ids = models.JSONField(default=list)
    max_ml_score = models.FloatField(null=True, blank=True)
    ml_threshold = models.FloatField(null=True, blank=True)
    max_ml_percentile = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=8)
    title = models.CharField(max_length=200)
    summary = models.TextField()
    provenance = models.CharField(max_length=32, blank=True, default="")
    quality_flags = models.JSONField(default=list)
    model_ids = models.JSONField(default=list)
    rule_versions = models.JSONField(default=dict)
    window_cfg_hash = models.CharField(max_length=16, blank=True, default="")
    decision_count = models.PositiveIntegerField(default=1)
    workflow_status = models.CharField(
        max_length=16, choices=WorkflowStatus.choices, default=WorkflowStatus.NEW
    )
    assessment = models.CharField(max_length=24, choices=Assessment.choices, default=Assessment.NEEDS_REVIEW)
    suppressed = models.BooleanField(default=False)
    suppression = models.ForeignKey(Suppression, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-window_end", "-id"]
        indexes = [models.Index(fields=["namespace", "domain", "window_end"], name="al_ns_dom_end")]


class AlertDecision(models.Model):
    """One raw decision (a window or upstream event) attached to a grouped alert."""

    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name="decisions")
    window = models.OneToOneField(
        "atd_features.FeatureWindow", null=True, blank=True, on_delete=models.CASCADE
    )
    upstream_event_id = models.CharField(max_length=64, null=True, blank=True, unique=True)
    detection_source = models.CharField(max_length=16, choices=DetectionSource.choices)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    rule_results = models.JSONField(default=list)
    ml = models.JSONField(default=dict)
    explanation = models.JSONField(default=dict)
    config_snapshot = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["window_start", "id"]


class TriageEvent(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name="triage")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    actor_label = models.CharField(max_length=150)
    from_status = models.CharField(max_length=16)
    to_status = models.CharField(max_length=16)
    from_assessment = models.CharField(max_length=24)
    to_assessment = models.CharField(max_length=24)
    note = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "id"]


class Notification(models.Model):
    """In-app notification only (no email/webhook in v1)."""

    alert = models.ForeignKey(Alert, null=True, blank=True, on_delete=models.CASCADE)
    level = models.CharField(max_length=8)
    message = models.CharField(max_length=300)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]


class UpstreamCheckpoint(models.Model):
    namespace = models.CharField(max_length=100, unique=True)
    last_event_pk = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
