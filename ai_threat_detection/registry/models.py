from __future__ import annotations

from django.conf import settings
from django.db import models


class ModelVersion(models.Model):
    STATUSES = [
        ("CANDIDATE", "Candidate"),
        ("ACTIVE", "Active"),
        ("RETIRED", "Retired"),
        ("FAILED", "Failed"),
        ("REJECTED", "Rejected"),
    ]
    model_id = models.CharField(max_length=64, unique=True)
    domain = models.CharField(max_length=16)
    feature_set = models.CharField(max_length=32)
    feature_schema_version = models.CharField(max_length=48)
    feature_order = models.JSONField()
    transforms = models.JSONField()
    window_config = models.JSONField()
    cfg_hash = models.CharField(max_length=16)
    algorithm = models.CharField(max_length=64, default="sklearn.ensemble.IsolationForest")
    hyperparameters = models.JSONField(default=dict)
    hyperparameter_trials = models.JSONField(default=list)
    random_state = models.IntegerField()
    status = models.CharField(max_length=16, choices=STATUSES, default="CANDIDATE")
    artifact_rel = models.CharField(max_length=300)
    artifact_sha256 = models.CharField(max_length=64)
    artifact_format = models.CharField(max_length=16, default="skops")
    artifact_signature = models.CharField(max_length=64)
    integrity_key_id = models.CharField(max_length=16)
    pseudonym_key_id = models.CharField(max_length=16, blank=True, default="")
    dependencies = models.JSONField(default=dict)
    experiment = models.ForeignKey(
        "atd_experiments.Experiment", null=True, blank=True, on_delete=models.SET_NULL
    )
    split_manifest_sha256 = models.CharField(max_length=64, blank=True, default="")
    train_cutoff = models.DateTimeField(null=True, blank=True)
    n_train = models.PositiveIntegerField(default=0)
    train_exclusions = models.JSONField(default=dict)
    training_seconds = models.FloatField(default=0.0)
    threshold = models.FloatField()
    threshold_version = models.PositiveIntegerField(default=1)
    threshold_criterion = models.JSONField(default=dict)
    score_transform = models.CharField(max_length=200)
    reference_score_quantiles = models.JSONField(default=list)
    baseline_stats = models.JSONField(default=dict)
    validation_metrics = models.JSONField(default=dict)
    test_metrics = models.JSONField(default=dict)
    model_card_rel = models.CharField(max_length=300, blank=True, default="")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.model_id


class ActiveModel(models.Model):
    domain = models.CharField(max_length=16, unique=True)
    model = models.ForeignKey(ModelVersion, on_delete=models.PROTECT)
    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    activated_at = models.DateTimeField(auto_now=True)
    reason = models.CharField(max_length=500)


class ActivationHistory(models.Model):
    domain = models.CharField(max_length=16)
    model = models.ForeignKey(ModelVersion, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    previous = models.ForeignKey(
        ModelVersion, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    action = models.CharField(max_length=24)
    actor_label = models.CharField(max_length=150)
    reason = models.CharField(max_length=500)
    details = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]


class MLDecision(models.Model):
    """ML output for a window. Status is explicit: no score is invented when the
    model is untrained, incompatible, failed, or the window lacks coverage."""

    STATUSES = [
        ("SCORED", "Scored"),
        ("INSUFFICIENT_DATA", "Insufficient data"),
        ("UNTRAINED", "Untrained"),
        ("INCOMPATIBLE", "Incompatible"),
        ("FAILED", "Failed"),
    ]
    window = models.ForeignKey("atd_features.FeatureWindow", on_delete=models.CASCADE)
    model = models.ForeignKey(ModelVersion, null=True, blank=True, on_delete=models.SET_NULL)
    model_key = models.CharField(max_length=64)
    status = models.CharField(max_length=24, choices=STATUSES)
    reason = models.CharField(max_length=200, blank=True, default="")
    score = models.FloatField(null=True, blank=True)
    threshold = models.FloatField(null=True, blank=True)
    threshold_version = models.PositiveIntegerField(null=True, blank=True)
    percentile = models.FloatField(null=True, blank=True)
    is_anomaly = models.BooleanField(null=True)
    model_stale = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["window", "model_key"], name="uniq_ml_decision")]
