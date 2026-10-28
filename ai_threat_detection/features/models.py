from __future__ import annotations

from django.db import models


class FeatureWindow(models.Model):
    """One entity x one event-time window of computed (redacted) feature values.

    ``capture_id`` is copied for experiment bookkeeping only; it is never a model input.
    """

    namespace = models.CharField(max_length=100)
    domain = models.CharField(max_length=16)
    cfg_hash = models.CharField(max_length=16)
    entity_key = models.CharField(max_length=40)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    available_at = models.DateTimeField()
    event_count = models.PositiveIntegerField()
    features = models.JSONField()
    coverage = models.JSONField()
    quality_flags = models.JSONField(default=list)
    capture_id = models.CharField(max_length=64, null=True, blank=True)
    sample_event_ids = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["namespace", "domain", "cfg_hash", "entity_key", "window_start"], name="uniq_window"
            )
        ]
        indexes = [
            models.Index(
                fields=["namespace", "domain", "cfg_hash", "window_start"], name="fw_ns_dom_cfg_start"
            )
        ]


class DetectionCheckpoint(models.Model):
    """All windows with start < processed_until are closed for (namespace, domain, cfg)."""

    namespace = models.CharField(max_length=100)
    domain = models.CharField(max_length=16)
    cfg_hash = models.CharField(max_length=16)
    window_config = models.JSONField(default=dict)
    processed_until = models.DateTimeField(null=True, blank=True)
    windows_built = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["namespace", "domain", "cfg_hash"], name="uniq_detection_checkpoint"
            )
        ]
