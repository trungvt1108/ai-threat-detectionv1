"""Feature / missingness / score drift of recent windows vs the active model's train baseline.

Drift is a health signal for the model's operating assumptions. It does not show
that an attack happened, and it never triggers automatic retraining.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from django.db.models import Count
from django.utils import timezone

from ai_threat_detection.ml.detector import psi
from ai_threat_detection.registry.models import MLDecision
from ai_threat_detection.registry.service import get_active_detector

from .models import FeatureWindow

PSI_BANDS = ((0.1, "ổn định"), (0.25, "lệch vừa"), (float("inf"), "lệch lớn"))


def _band(v: float | None) -> str:
    if v is None:
        return "N/A"
    for limit, name in PSI_BANDS:
        if v < limit:
            return name
    return PSI_BANDS[-1][1]


def drift_report(domain: str, namespace: str = "live", last_n: int = 2000) -> dict[str, Any]:
    det = get_active_detector(domain)
    mv = det.model_version
    out: dict[str, Any] = {
        "domain": domain,
        "namespace": namespace,
        "ml_status": det.status,
        "ml_reason": det.reason,
        "note": "Drift là tín hiệu sức khỏe của giả định model; không chứng minh có tấn công và không tự retrain.",
    }
    if mv is None:
        out["available"] = False
        return out
    windows = list(
        FeatureWindow.objects.filter(namespace=namespace, domain=domain, cfg_hash=mv.cfg_hash).order_by(
            "-created_at"
        )[:last_n]
    )
    out.update(
        {
            "available": True,
            "model_id": mv.model_id,
            "model_age_days": round((timezone.now() - mv.created_at).total_seconds() / 86400, 2),
            "recent_windows": len(windows),
            "reference": f"train baseline of {mv.model_id} (n={mv.n_train})",
        }
    )
    feats = []
    for name in mv.feature_order:
        b = mv.baseline_stats.get(name)
        vals = [float(w.features[name]) for w in windows if w.features.get(name) is not None]
        missing = sum(1 for w in windows if w.features.get(name) is None)
        p = psi(b["bin_edges"], b["bin_props"], vals) if b and "bin_edges" in b else None
        feats.append(
            {
                "feature": name,
                "psi": None if p is None else round(p, 4),
                "band": _band(p),
                "n": len(vals),
                "missing": missing,
                "baseline_median": b["q50"] if b else None,
                "recent_median": float(np.median(vals)) if vals else None,
            }
        )
    out["features"] = feats
    statuses = dict(
        MLDecision.objects.filter(window__in=[w.pk for w in windows], model=mv)
        .values_list("status")
        .annotate(n=Count("id"))
    )
    total = sum(statuses.values())
    out["ml_status_counts"] = statuses
    out["abstain_ratio_recent"] = (statuses.get("INSUFFICIENT_DATA", 0) / total) if total else None
    ex = mv.train_exclusions or {}
    denom = mv.n_train + ex.get("ml_ineligible_windows", 0)
    out["abstain_ratio_train"] = (ex.get("ml_ineligible_windows", 0) / denom) if denom else None
    scores = list(
        MLDecision.objects.filter(window__in=[w.pk for w in windows], model=mv, status="SCORED").values_list(
            "score", flat=True
        )
    )
    ref = mv.reference_score_quantiles
    out["score"] = {
        "recent_median": float(np.median(scores)) if scores else None,
        "recent_p95": float(np.quantile(scores, 0.95)) if scores else None,
        "train_median": ref[50] if ref else None,
        "train_p95": ref[95] if ref else None,
        "recent_above_threshold": sum(1 for s in scores if s >= mv.threshold),
        "n": len(scores),
    }
    return out
