"""Detection pipeline: closed windows -> rules + ML (stored separately) -> grouped alerts."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from ai_threat_detection.features.builder import build_windows
from ai_threat_detection.features.models import DetectionCheckpoint, FeatureWindow
from ai_threat_detection.features.spec import DEFAULT_FEATURE_SET, WindowConfig, get_feature_set
from ai_threat_detection.ml.detector import anomaly_scores, build_matrix, deviations, score_percentile
from ai_threat_detection.registry.models import MLDecision
from ai_threat_detection.registry.service import ActiveDetector, get_active_detector
from ai_threat_detection.rules.engine import RuleResult, evaluate_all
from ai_threat_detection.rules.models import RuleDecision
from ai_threat_detection.rules.service import current_rules, rule_versions_snapshot
from ai_threat_detection.sources.models import Event

from . import policy
from .models import Alert, AlertDecision, Notification, Suppression, UpstreamCheckpoint


def detection_config(domain: str) -> tuple[WindowConfig, str, ActiveDetector]:
    det = get_active_detector(domain)
    if det.model_version is not None:
        return WindowConfig.from_dict(det.model_version.window_config), det.model_version.feature_set, det
    return WindowConfig(), DEFAULT_FEATURE_SET[domain], det


def ml_decisions(
    windows: list[FeatureWindow], det: ActiveDetector, cfg: WindowConfig
) -> list[dict[str, Any]]:
    """One dict per window, same order. Never invents a score."""
    if not windows:
        return []
    if not det.usable:
        return [
            {
                "status": det.status,
                "reason": det.reason,
                "model_id": det.model_version.model_id if det.model_version else None,
            }
            for _ in windows
        ]
    mv = det.model_version
    if mv is None or det.model is None:  # usable implies both; keep the invariant explicit
        raise RuntimeError("usable detector without model")
    if mv.cfg_hash != cfg.config_hash():
        return [
            {"status": "INCOMPATIBLE", "reason": "window config differs from model", "model_id": mv.model_id}
            for _ in windows
        ]
    fs = get_feature_set(mv.feature_set)
    mat = build_matrix(fs, windows, cfg)
    scores = anomaly_scores(det.model, mat.X)
    out: list[dict[str, Any]] = [{} for _ in windows]
    for i, reason in mat.abstain.items():
        out[i] = {"status": "INSUFFICIENT_DATA", "reason": reason, "model_id": mv.model_id}
    for j, i in enumerate(mat.eligible_idx):
        s = float(scores[j])
        out[i] = {
            "status": "SCORED",
            "score": s,
            "threshold": mv.threshold,
            "threshold_version": mv.threshold_version,
            "percentile": score_percentile(s, mv.reference_score_quantiles),
            "percentile_reference": f"train scores of {mv.model_id} (n={mv.n_train})",
            "is_anomaly": s >= mv.threshold,
            "model_id": mv.model_id,
            "model_stale": det.status == "STALE",
            "deviations": deviations(fs, windows[i].features, mv.baseline_stats),
        }
    return out


def _active_suppression(domain: str, entity: str, rule_ids: list[str], source: str) -> Suppression | None:
    now = timezone.now()
    for s in Suppression.objects.filter(domain=domain, revoked_at__isnull=True, expires_at__gt=now):
        if s.entity_key and s.entity_key != entity:
            continue
        if s.rule_id and s.rule_id not in rule_ids:
            continue
        if s.detection_source and s.detection_source != source:
            continue
        return s
    return None


def _provenance(window: FeatureWindow) -> str:
    ev = (
        Event.objects.filter(event_id__in=window.sample_event_ids[:1])
        .values_list("provenance", flat=True)
        .first()
    )
    return ev or ""


def _attach_or_create(
    *,
    namespace: str,
    domain: str,
    entity: str,
    source: str,
    severity: str,
    title: str,
    summary: str,
    start: datetime,
    end: datetime,
    rule_ids: list[str],
    ml: dict[str, Any],
    decision_kwargs: dict[str, Any],
    provenance: str,
    quality_flags: list[str],
    model_id: str | None,
    rule_versions: dict[str, int],
    cfg_hash: str,
) -> tuple[Alert, bool]:
    group_key = f"{namespace}|{domain}|{entity}"
    existing = (
        Alert.objects.filter(group_key=group_key)
        .exclude(workflow_status="CLOSED")
        .order_by("-window_end")
        .first()
    )
    if (
        existing is not None
        and start - existing.window_end <= policy.COOLDOWN
        and end >= existing.window_start
    ):
        existing.window_end = max(existing.window_end, end)
        existing.window_start = min(existing.window_start, start)
        existing.detection_source = policy.merge_sources(existing.detection_source, source)
        existing.severity = policy.max_severity(existing.severity, severity)
        existing.rule_ids = sorted(set(existing.rule_ids) | set(rule_ids))
        if ml.get("status") == "SCORED" and ml.get("is_anomaly"):
            existing.max_ml_score = max(existing.max_ml_score or 0.0, ml["score"])
            existing.ml_threshold = ml["threshold"]
            existing.max_ml_percentile = max(existing.max_ml_percentile or 0.0, ml["percentile"])
        existing.quality_flags = sorted(set(existing.quality_flags) | set(quality_flags))
        if model_id and model_id not in existing.model_ids:
            existing.model_ids = existing.model_ids + [model_id]
        existing.rule_versions = {**existing.rule_versions, **rule_versions}
        existing.decision_count += 1
        existing.save()
        AlertDecision.objects.create(
            alert=existing, detection_source=source, window_start=start, window_end=end, **decision_kwargs
        )
        return existing, False
    sup = _active_suppression(domain, entity, rule_ids, source)
    alert = Alert.objects.create(
        namespace=namespace,
        domain=domain,
        entity_key=entity,
        group_key=group_key,
        window_start=start,
        window_end=end,
        detection_source=source,
        rule_ids=sorted(rule_ids),
        max_ml_score=ml.get("score") if ml.get("is_anomaly") else None,
        ml_threshold=ml.get("threshold") if ml.get("is_anomaly") else None,
        max_ml_percentile=ml.get("percentile") if ml.get("is_anomaly") else None,
        severity=severity,
        title=title[:200],
        summary=summary,
        provenance=provenance,
        quality_flags=sorted(set(quality_flags)),
        model_ids=[model_id] if model_id else [],
        rule_versions=rule_versions,
        window_cfg_hash=cfg_hash,
        suppressed=sup is not None,
        suppression=sup,
    )
    AlertDecision.objects.create(
        alert=alert, detection_source=source, window_start=start, window_end=end, **decision_kwargs
    )
    if sup is None and policy.SEVERITY_ORDER.get(severity, 0) >= policy.SEVERITY_ORDER["medium"]:
        Notification.objects.create(alert=alert, level=severity, message=title[:300])
    return alert, True


def _title_summary(
    domain: str, source: str, triggered: list[RuleResult], ml: dict[str, Any], w: FeatureWindow
) -> tuple[str, str]:
    parts = []
    if triggered:
        names = "; ".join(f"{r.rule_id} {r.name}" for r in triggered)
        parts.append(names)
        for r in triggered:
            obs = ", ".join(f"{k}={_fmt(v)}" for k, v in r.observed.items())
            thr = ", ".join(f"{t['feature']} {t['op']} {_fmt(t['value'])}" for t in r.thresholds)
            parts.append(f"[{r.rule_id}] quan sát: {obs} | ngưỡng: {thr}")
    if ml.get("status") == "SCORED" and ml.get("is_anomaly"):
        parts.append(
            f"[ML {ml['model_id']}] anomaly score {ml['score']:.3f} >= ngưỡng {ml['threshold']:.3f} "
            f"(bách phân vị {ml['percentile']:.0f} so với điểm train; không phải xác suất tấn công)"
        )
    title = (
        f"{triggered[0].rule_id} {triggered[0].name}"
        if triggered
        else f"Bất thường {domain} (IsolationForest) cần review"
    )
    if source == "RULE_AND_ML":
        title += " + ML"
    window = (
        f"Cửa sổ {w.window_start:%Y-%m-%d %H:%M:%S}–{w.window_end:%H:%M:%S} UTC, {w.event_count} sự kiện."
    )
    return title, window + "\n" + "\n".join(parts)


def _fmt(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".")
    return str(v)


def process_windows(
    namespace: str, domain: str, windows: list[FeatureWindow], cfg: WindowConfig, det: ActiveDetector
) -> dict[str, Any]:
    rules = current_rules(domain)
    versions = {k: v for k, v in rule_versions_snapshot().items() if any(r.rule_id == k for r in rules)}
    mls = ml_decisions(windows, det, cfg)
    stats: Counter[str] = Counter()
    cfg_hash = cfg.config_hash()
    for w, ml in zip(windows, mls, strict=True):
        with transaction.atomic():
            results = evaluate_all(rules, domain, w.features)
            for r in results:
                stats[f"rule_{r.status.lower()}"] += 1
            RuleDecision.objects.bulk_create(
                [
                    RuleDecision(
                        window=w,
                        namespace=namespace,
                        domain=domain,
                        rule_id=r.rule_id,
                        rule_version=r.version,
                        status=r.status,
                        observed=r.observed,
                        thresholds=r.thresholds,
                        missing=r.missing,
                        context={"cfg_hash": cfg_hash},
                    )
                    for r in results
                    if r.status != "NOT_TRIGGERED"
                ],
                ignore_conflicts=True,
            )
            MLDecision.objects.get_or_create(
                window=w,
                model_key=ml.get("model_id") or "none",
                defaults={
                    "model": det.model_version if ml.get("model_id") and det.model_version else None,
                    "status": ml["status"],
                    "reason": (ml.get("reason") or "")[:200],
                    "score": ml.get("score"),
                    "threshold": ml.get("threshold"),
                    "threshold_version": ml.get("threshold_version"),
                    "percentile": ml.get("percentile"),
                    "is_anomaly": ml.get("is_anomaly"),
                    "model_stale": bool(ml.get("model_stale")),
                },
            )
            stats[f"ml_{ml['status'].lower()}"] += 1
            triggered = [r for r in results if r.status == "TRIGGERED"]
            ml_hit = ml.get("status") == "SCORED" and bool(ml.get("is_anomaly"))
            source = policy.combine_source(bool(triggered), ml_hit)
            if source is None or AlertDecision.objects.filter(window=w).exists():
                continue
            sev = policy.severity_for(source, [r.severity for r in triggered])
            title, summary = _title_summary(domain, source, triggered, ml, w)
            explanation = {
                "window": {
                    "start": w.window_start.isoformat(),
                    "end": w.window_end.isoformat(),
                    "events": w.event_count,
                    "available_at": w.available_at.isoformat(),
                    "cfg_hash": cfg_hash,
                    "window_config": cfg.to_dict(),
                },
                "features": w.features,
                "coverage": w.coverage,
                "rules": [r.to_dict() for r in results if r.status != "NOT_TRIGGERED"],
                "ml": {k: v for k, v in ml.items()},
                "ml_explanation_note": "Độ lệch so với baseline train (median/IQR); không phải đóng góp của model.",
                "policy_version": policy.POLICY_VERSION,
            }
            _, created = _attach_or_create(
                namespace=namespace,
                domain=domain,
                entity=w.entity_key,
                source=source,
                severity=sev,
                title=title,
                summary=summary,
                start=w.window_start,
                end=w.window_end,
                rule_ids=[r.rule_id for r in triggered],
                ml=ml,
                decision_kwargs={
                    "window": w,
                    "rule_results": [r.to_dict() for r in triggered],
                    "ml": {k: v for k, v in ml.items() if k != "deviations"},
                    "explanation": explanation,
                    "config_snapshot": {
                        "rule_versions": versions,
                        "model_id": ml.get("model_id"),
                        "threshold_version": ml.get("threshold_version"),
                        "cfg_hash": cfg_hash,
                        "policy": policy.POLICY_VERSION,
                    },
                },
                provenance=_provenance(w),
                quality_flags=w.quality_flags,
                model_id=ml.get("model_id") if ml_hit else None,
                rule_versions=versions,
                cfg_hash=cfg_hash,
            )
            stats["alerts_created" if created else "decisions_attached"] += 1
    stats["windows"] = len(windows)
    return dict(stats)


def run_detection(
    namespace: str,
    domain: str,
    watermark: datetime | None = None,
    finalize: bool = False,
    ctx=None,
    cfg: WindowConfig | None = None,
) -> dict[str, Any]:
    if domain not in DEFAULT_FEATURE_SET:
        raise ValueError(f"No window features/model for domain {domain} (UPSTREAM_ONLY or unsupported)")
    use_cfg, fs_name, det = detection_config(domain)
    if cfg is not None:
        use_cfg = cfg
    if not DetectionCheckpoint.objects.filter(
        namespace=namespace, domain=domain, cfg_hash=use_cfg.config_hash()
    ).exists():
        # A new window config continues from where other configs stopped for this namespace
        # instead of re-alerting on all history.
        prev = DetectionCheckpoint.objects.filter(namespace=namespace, domain=domain).aggregate(
            m=Max("processed_until")
        )["m"]
        if prev is not None:
            from ai_threat_detection.features.compute import floor_time

            DetectionCheckpoint.objects.create(
                namespace=namespace,
                domain=domain,
                cfg_hash=use_cfg.config_hash(),
                window_config=use_cfg.to_dict(),
                processed_until=floor_time(prev, use_cfg.stride_s),
            )
    windows = build_windows(namespace, domain, use_cfg, watermark=watermark, finalize=finalize, ctx=ctx)
    stats = process_windows(namespace, domain, windows, use_cfg, det)
    stats.update(
        {
            "ml_status": det.status,
            "ml_reason": det.reason,
            "feature_set": fs_name,
            "cfg_hash": use_cfg.config_hash(),
        }
    )
    return stats


def process_upstream_ids(namespace: str) -> dict[str, int]:
    """Suricata EVE alerts -> UPSTREAM_IDS alerts (grouped). Never scored by project models."""
    cp, _ = UpstreamCheckpoint.objects.get_or_create(namespace=namespace)
    qs = Event.objects.filter(namespace=namespace, domain="EVE_ALERT", pk__gt=cp.last_event_pk).order_by("pk")
    created = attached = 0
    last = cp.last_event_pk
    for ev in qs.iterator(chunk_size=500):
        last = ev.pk
        if AlertDecision.objects.filter(upstream_event_id=ev.event_id).exists():
            continue
        ua = ev.fields.get("upstream_alert") or {}
        sev = policy.severity_for("UPSTREAM_IDS", [], ua.get("severity"))
        title = f"Upstream IDS: {ua.get('signature') or 'signature?'} (sid {ua.get('signature_id')})"
        summary = (
            f"Tín hiệu từ Suricata (sensor {ev.fields.get('sensor')}), không phải phát hiện của model dự án. "
            f"Mức độ theo upstream: {ua.get('severity')}. Correlation key: {ev.fields.get('correlation_key')}."
        )
        _, was_created = _attach_or_create(
            namespace=namespace,
            domain="EVE",
            entity=ev.entity_key or "",
            source="UPSTREAM_IDS",
            severity=sev,
            title=title,
            summary=summary,
            start=ev.event_time,
            end=ev.event_time,
            rule_ids=[],
            ml={},
            decision_kwargs={
                "upstream_event_id": ev.event_id,
                "explanation": {
                    "upstream_alert": ua,
                    "sensor": ev.fields.get("sensor"),
                    "correlation_key": ev.fields.get("correlation_key"),
                },
            },
            provenance=ev.provenance,
            quality_flags=ev.quality_flags,
            model_id=None,
            rule_versions={},
            cfg_hash="",
        )
        created += int(was_created)
        attached += int(not was_created)
    cp.last_event_pk = last
    cp.save()
    return {"upstream_alerts_created": created, "upstream_decisions_attached": attached}
