from __future__ import annotations

from django.conf import settings
from django.db import models


class Provenance(models.TextChoices):
    SYNTHETIC_DEMO = "SYNTHETIC_DEMO", "Synthetic demo"
    LAB_OBSERVED = "LAB_OBSERVED", "Lab observed"
    USER_IMPORTED = "USER_IMPORTED", "User imported"
    PUBLIC_DATASET = "PUBLIC_DATASET", "Public dataset"
    LIVE_FOLLOW = "LIVE_FOLLOW", "Live follow"


class PrivacyClass(models.TextChoices):
    PRIVATE = "PRIVATE", "Private"
    LAB = "LAB", "Lab"
    DEMO = "DEMO", "Demo"
    PUBLIC_LICENSED = "PUBLIC_LICENSED", "Public (licensed)"


class SourceType(models.TextChoices):
    HTTP_JSON = "http_json", "HTTP access JSON/NDJSON"
    HTTP_COMBINED = "http_combined", "HTTP access text (nginx/Apache common/combined)"
    AUTH_JSON = "auth_json", "Authentication JSON/NDJSON"
    AUTH_SYSLOG = "auth_syslog", "SSH auth text (sshd lines in auth.log/secure)"
    SURICATA_EVE = "suricata_eve", "Suricata EVE JSON (alert/flow)"


class Source(models.Model):
    """An explicitly registered log location. Root must be inside ATD_ALLOWED_SOURCE_ROOTS."""

    name = models.SlugField(max_length=64, unique=True)
    source_type = models.CharField(max_length=32, choices=SourceType.choices)
    root_path = models.CharField(max_length=1024)
    file_pattern = models.CharField(max_length=128, default="*.ndjson")
    provenance = models.CharField(max_length=32, choices=Provenance.choices, default=Provenance.USER_IMPORTED)
    privacy_class = models.CharField(
        max_length=32, choices=PrivacyClass.choices, default=PrivacyClass.PRIVATE
    )
    assume_timezone = models.CharField(max_length=64, blank=True, default="")
    sensor_name = models.CharField(max_length=64, default="default")
    stable_id_field = models.CharField(max_length=64, blank=True, default="")
    pseudonym_scope = models.CharField(max_length=64, default="global")
    store_raw_identity = models.BooleanField(default=False)
    store_invalid_preview = models.BooleanField(default=False)
    stale_after_seconds = models.PositiveIntegerField(default=900)
    expected_max_gap_seconds = models.PositiveIntegerField(null=True, blank=True)
    license_note = models.CharField(max_length=500, blank=True, default="")
    usage_constraints = models.CharField(max_length=500, blank=True, default="")
    enabled = models.BooleanField(default=True)
    config_version = models.PositiveIntegerField(default=1)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class SourceCheckpoint(models.Model):
    """Per (source, namespace, file identity) read position; updated in the same
    transaction as the events of each chunk."""

    source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name="checkpoints")
    namespace = models.CharField(max_length=100, default="live")
    file_key = models.CharField(max_length=64)
    file_rel = models.CharField(max_length=512)
    offset = models.BigIntegerField(default=0)
    line_no = models.BigIntegerField(default=0)
    size_seen = models.BigIntegerField(default=0)
    stat_id = models.CharField(max_length=64, blank=True, default="")
    is_current = models.BooleanField(default=True)
    completed = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["source", "namespace", "file_key"], name="uniq_checkpoint_file")
        ]


class IngestRun(models.Model):
    MODES = [("IMPORT", "Import"), ("REPLAY", "Replay"), ("FOLLOW", "Follow")]
    source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name="runs")
    job_id = models.BigIntegerField(null=True, blank=True)
    mode = models.CharField(max_length=16, choices=MODES)
    namespace = models.CharField(max_length=100, default="live", db_index=True)
    file_rel = models.CharField(max_length=512, blank=True, default="")
    file_key = models.CharField(max_length=64, blank=True, default="")
    status = models.CharField(max_length=24, default="RUNNING")
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    records_seen = models.BigIntegerField(default=0)
    accepted = models.BigIntegerField(default=0)
    duplicates = models.BigIntegerField(default=0)
    rejected = models.BigIntegerField(default=0)
    blank_lines = models.BigIntegerField(default=0)
    # Lines a text adapter deliberately ignores (e.g. cron/sudo lines in auth.log).
    # They are not parse failures and do not count towards parse_failure_ratio.
    skipped = models.BigIntegerField(default=0)
    skip_reasons = models.JSONField(default=dict)
    partial_pending = models.BigIntegerField(default=0)
    late_events = models.BigIntegerField(default=0)
    future_events = models.BigIntegerField(default=0)
    reject_reasons = models.JSONField(default=dict)
    quality_flag_counts = models.JSONField(default=dict)
    first_event_time = models.DateTimeField(null=True, blank=True)
    last_event_time = models.DateTimeField(null=True, blank=True)
    max_event_gap_seconds = models.FloatField(null=True, blank=True)
    notes = models.JSONField(default=list)

    class Meta:
        ordering = ["-started_at"]

    @property
    def parse_failure_ratio(self) -> float | None:
        total = self.accepted + self.duplicates + self.rejected
        return (self.rejected / total) if total else None


class Event(models.Model):
    """Canonical, redacted event. ``fields`` holds only adapter-allowlisted values."""

    event_id = models.CharField(max_length=64, unique=True)
    namespace = models.CharField(max_length=100, default="live")
    source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name="events")
    source_type = models.CharField(max_length=32)
    schema_version = models.CharField(max_length=32)
    domain = models.CharField(max_length=16)
    event_time = models.DateTimeField()
    ingested_at = models.DateTimeField()
    file_key = models.CharField(max_length=64)
    offset = models.BigIntegerField()
    line_no = models.BigIntegerField()
    provenance = models.CharField(max_length=32, choices=Provenance.choices)
    privacy_class = models.CharField(max_length=32, choices=PrivacyClass.choices)
    entity_key = models.CharField(max_length=40, null=True, blank=True)
    user_key = models.CharField(max_length=40, null=True, blank=True)
    host_key = models.CharField(max_length=40, null=True, blank=True)
    fields = models.JSONField(default=dict)
    quality_flags = models.JSONField(default=list)
    capture_id = models.CharField(max_length=64, null=True, blank=True)
    ingest_run = models.ForeignKey(IngestRun, null=True, blank=True, on_delete=models.SET_NULL)
    excluded_from_windows = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=["namespace", "domain", "event_time"], name="ev_ns_dom_time"),
            models.Index(
                fields=["namespace", "domain", "entity_key", "event_time"], name="ev_ns_dom_ent_time"
            ),
            models.Index(fields=["ingested_at"], name="ev_ingested"),
        ]


class RejectedRecord(models.Model):
    """Rejected input: locator + hash + reason. Never the raw line; a scrubbed
    preview only if the source explicitly enables it."""

    source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name="rejected")
    namespace = models.CharField(max_length=100, default="live")
    ingest_run = models.ForeignKey(IngestRun, null=True, blank=True, on_delete=models.SET_NULL)
    file_key = models.CharField(max_length=64)
    offset = models.BigIntegerField()
    line_no = models.BigIntegerField()
    reason = models.CharField(max_length=64, db_index=True)
    content_sha256 = models.CharField(max_length=64, blank=True, default="")
    preview = models.CharField(max_length=200, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source", "namespace", "file_key", "offset"], name="uniq_rejected_locator"
            )
        ]


class RawIdentity(models.Model):
    """Pseudonym -> raw value. Only populated for sources with store_raw_identity=True;
    visible only to admins when ATD_ALLOW_RAW_IDENTITY_VIEW is on; never exported."""

    pseudonym = models.CharField(max_length=40, unique=True)
    kind = models.CharField(max_length=16)
    raw_value = models.CharField(max_length=256)
    source = models.ForeignKey(Source, on_delete=models.CASCADE)
    first_seen = models.DateTimeField(auto_now_add=True)


class SourceHealth(models.Model):
    STATUSES = [
        ("OK", "OK"),
        ("NEVER_RUN", "Never run"),
        ("STALE", "Stale"),
        ("MISSING", "File missing"),
        ("PERMISSION_DENIED", "Permission denied"),
        ("ERROR", "Error"),
    ]
    source = models.OneToOneField(Source, on_delete=models.CASCADE, related_name="health")
    status = models.CharField(max_length=24, choices=STATUSES, default="NEVER_RUN")
    detail = models.CharField(max_length=300, blank=True, default="")
    last_poll_at = models.DateTimeField(null=True, blank=True)
    last_data_at = models.DateTimeField(null=True, blank=True)
    last_event_time = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
