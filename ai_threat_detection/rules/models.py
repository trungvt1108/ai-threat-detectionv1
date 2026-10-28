from __future__ import annotations

from django.conf import settings
from django.db import models


class RuleConfig(models.Model):
    """Versioned rule definition. Edits create a new version row (never in-place)."""

    rule_id = models.CharField(max_length=16)
    version = models.PositiveIntegerField()
    domain = models.CharField(max_length=16)
    definition = models.JSONField()
    enabled = models.BooleanField(default=True)
    is_current = models.BooleanField(default=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    actor_label = models.CharField(max_length=150, default="system")
    reason = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["rule_id", "version"], name="uniq_rule_version")]
        ordering = ["rule_id", "-version"]


class RuleDecision(models.Model):
    """Rule output for a window (TRIGGERED / NOT_EVALUABLE stored; NOT_TRIGGERED counted only)."""

    window = models.ForeignKey("atd_features.FeatureWindow", null=True, blank=True, on_delete=models.CASCADE)
    namespace = models.CharField(max_length=100)
    domain = models.CharField(max_length=16)
    rule_id = models.CharField(max_length=16)
    rule_version = models.PositiveIntegerField()
    status = models.CharField(max_length=16)
    observed = models.JSONField(default=dict)
    thresholds = models.JSONField(default=list)
    missing = models.JSONField(default=list)
    context = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["window", "rule_id", "rule_version"], name="uniq_rule_decision_window"
            )
        ]
