from __future__ import annotations

from django.conf import settings
from django.db import models


class Dataset(models.Model):
    dataset_id = models.SlugField(max_length=64, unique=True)
    name = models.CharField(max_length=200)
    provenance = models.CharField(max_length=32)
    privacy_class = models.CharField(max_length=32)
    license = models.CharField(max_length=200, blank=True, default="")
    usage_constraints = models.CharField(max_length=500, blank=True, default="")
    description = models.TextField(blank=True, default="")
    root_rel = models.CharField(max_length=300)
    manifest_sha256 = models.CharField(max_length=64)
    generator = models.JSONField(default=dict)
    label_definition = models.JSONField(default=dict)
    status = models.CharField(max_length=16, default="REGISTERED")
    pseudonym_key_id = models.CharField(max_length=16, blank=True, default="")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.dataset_id


class Capture(models.Model):
    dataset = models.ForeignKey(Dataset, on_delete=models.CASCADE, related_name="captures")
    capture_id = models.CharField(max_length=64)
    scenario_group = models.CharField(max_length=64)
    start = models.DateTimeField()
    end = models.DateTimeField()
    files = models.JSONField(default=dict)
    labels_rel = models.CharField(max_length=300)
    labels_sha256 = models.CharField(max_length=64)
    background_label = models.CharField(max_length=24, default="UNKNOWN")
    namespace = models.CharField(max_length=100)
    imported = models.BooleanField(default=False)
    import_stats = models.JSONField(default=dict)
    description = models.CharField(max_length=300, blank=True, default="")

    class Meta:
        ordering = ["start"]
        constraints = [models.UniqueConstraint(fields=["dataset", "capture_id"], name="uniq_capture")]


class Experiment(models.Model):
    exp_id = models.SlugField(max_length=64, unique=True)
    dataset = models.ForeignKey(Dataset, on_delete=models.PROTECT, related_name="experiments")
    name = models.CharField(max_length=200)
    protocol_version = models.CharField(max_length=32)
    window_config = models.JSONField()
    cfg_hash = models.CharField(max_length=16)
    feature_sets = models.JSONField()
    random_state = models.IntegerField(default=20260101)
    split_manifest_rel = models.CharField(max_length=300, blank=True, default="")
    split_manifest_sha256 = models.CharField(max_length=64, blank=True, default="")
    status = models.CharField(max_length=24, default="CREATED")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.exp_id


class EvaluationRun(models.Model):
    experiment = models.ForeignKey(Experiment, on_delete=models.CASCADE, related_name="evaluations")
    domain = models.CharField(max_length=16)
    split = models.CharField(max_length=16)
    model = models.ForeignKey("atd_registry.ModelVersion", null=True, blank=True, on_delete=models.SET_NULL)
    run_index = models.PositiveIntegerField(default=1)
    test_previously_seen = models.BooleanField(default=False)
    rerun_reason = models.CharField(max_length=500, blank=True, default="")
    metrics = models.JSONField(default=dict)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
