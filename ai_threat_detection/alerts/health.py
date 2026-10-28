"""Data-quality / source-health alerts (detection source DATA_QUALITY, domain HEALTH).

A failed or silent source is reported as a health problem, never as "no threats".
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.utils import timezone

from ai_threat_detection.rules.engine import evaluate_all
from ai_threat_detection.rules.service import current_rules, rule_versions_snapshot
from ai_threat_detection.sources.models import IngestRun, Source, SourceHealth

from . import policy
from .detection import _attach_or_create


def ingest_metrics(run: IngestRun) -> dict[str, Any]:
    total = run.accepted + run.duplicates + run.rejected
    exp_gap = run.source.expected_max_gap_seconds
    return {
        "parse_failure_ratio": (run.rejected / total) if total else None,
        "records_total": total,
        "rejected": run.rejected,
        "gap_over_expected_ratio": (run.max_event_gap_seconds / exp_gap)
        if (exp_gap and run.max_event_gap_seconds is not None)
        else None,
        "late_events": run.late_events,
        "future_events": run.future_events,
        "stale_ratio": None,
    }


def staleness_metrics(source: Source) -> dict[str, Any]:
    h = SourceHealth.objects.filter(source=source).first()
    if h is None or h.last_data_at is None or not source.stale_after_seconds:
        return {"stale_ratio": None}
    return {"stale_ratio": (timezone.now() - h.last_data_at).total_seconds() / source.stale_after_seconds}


def _raise(
    source: Source,
    namespace: str,
    metrics: dict[str, Any],
    rule_filter: set[str] | None,
    span: tuple[datetime | None, datetime | None] = (None, None),
) -> list[str]:
    rules = [r for r in current_rules("HEALTH") if rule_filter is None or r.rule_id in rule_filter]
    triggered = [r for r in evaluate_all(rules, "HEALTH", metrics) if r.status == "TRIGGERED"]
    out = []
    now = timezone.now()
    start, end = span[0] or now, span[1] or span[0] or now
    versions = {k: v for k, v in rule_versions_snapshot().items() if k.startswith("HLTH")}
    for r in triggered:
        obs = ", ".join(f"{k}={v:.3f}" if isinstance(v, float) else f"{k}={v}" for k, v in r.observed.items())
        alert, _ = _attach_or_create(
            namespace=namespace,
            domain="HEALTH",
            entity=f"source:{source.name}",
            source="DATA_QUALITY",
            severity=r.severity,
            title=f"{r.rule_id} {r.name} — nguồn {source.name}",
            summary=f"Quan sát: {obs}. {r.limitation}",
            start=start,
            end=end,
            rule_ids=[r.rule_id],
            ml={},
            decision_kwargs={
                "rule_results": [r.to_dict()],
                "explanation": {"metrics": metrics, "policy": policy.POLICY_VERSION},
            },
            provenance=source.provenance,
            quality_flags=[],
            model_id=None,
            rule_versions=versions,
            cfg_hash="",
        )
        out.append(r.rule_id)
    return out


def evaluate_ingest_health(run: IngestRun) -> list[str]:
    span = (run.first_event_time, run.last_event_time)
    return _raise(run.source, run.namespace, ingest_metrics(run), {"HLTH-001", "HLTH-003"}, span)


def evaluate_staleness(source: Source, namespace: str = "live") -> list[str]:
    return _raise(source, namespace, staleness_metrics(source), {"HLTH-002"})
