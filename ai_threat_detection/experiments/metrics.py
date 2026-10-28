"""Evaluation metrics on entity-window units (pure functions, no Django).

Undefined metrics are ``None`` (rendered "N/A") with the support that explains why;
they are never coerced to 0 or 100%.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix

LABELS = ("SUSPICIOUS_PATTERN", "OPERATIONAL_ANOMALY", "AUTHORIZED_LOAD", "BENIGN", "UNKNOWN")
LABEL_PRECEDENCE = {"SUSPICIOUS_PATTERN": 3, "OPERATIONAL_ANOMALY": 2, "AUTHORIZED_LOAD": 1, "BENIGN": 0}

TASKS: dict[str, dict[str, Any]] = {
    "T1_SUSPICIOUS": {
        "description": "Positive = cửa sổ chứa hành vi mẫu đáng ngờ (SUSPICIOUS_PATTERN). "
        "Negative = BENIGN, OPERATIONAL_ANOMALY, AUTHORIZED_LOAD. UNKNOWN bị loại.",
        "positive": {"SUSPICIOUS_PATTERN"},
        "negative": {"BENIGN", "OPERATIONAL_ANOMALY", "AUTHORIZED_LOAD"},
        "rule_scope": "threat",
    },
    "T2_ANOMALOUS": {
        "description": "Positive = cửa sổ lệch khỏi hoạt động nền (SUSPICIOUS_PATTERN, OPERATIONAL_ANOMALY, "
        "AUTHORIZED_LOAD). Negative = BENIGN. UNKNOWN bị loại.",
        "positive": {"SUSPICIOUS_PATTERN", "OPERATIONAL_ANOMALY", "AUTHORIZED_LOAD"},
        "negative": {"BENIGN"},
        "rule_scope": "any",
    },
}
METHODS = ("rules_only", "ml_only", "hybrid_or")


def binary_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, Any]:
    yt = np.asarray(y_true, dtype=int)
    yp = np.asarray(y_pred, dtype=int)
    if len(yt) == 0:
        return {
            "support_total": 0,
            "support_positive": 0,
            "support_negative": 0,
            "precision": None,
            "recall": None,
            "f1": None,
            "accuracy": None,
            "confusion": None,
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
        }
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(yt, yp, labels=[0, 1]).ravel())
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "support_total": int(len(yt)),
        "support_positive": int(yt.sum()),
        "support_negative": int(len(yt) - yt.sum()),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "confusion": {"labels": ["neg", "pos"], "matrix_rows_true_cols_pred": [[tn, fp], [fn, tp]]},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": (tp + tn) / len(yt),
        "fpr": fp / (fp + tn) if (fp + tn) else None,
    }


def group_alerts(units: Sequence[dict], pred_key: str, cooldown: timedelta) -> list[dict]:
    """Group positive predictions per entity when consecutive windows are within cooldown."""
    by_entity: dict[str, list[dict]] = defaultdict(list)
    for u in units:
        if u[pred_key]:
            by_entity[u["entity"]].append(u)
    groups = []
    for ent, us in by_entity.items():
        us.sort(key=lambda x: x["start"])
        cur: list[dict] = []
        for u in us:
            if cur and u["start"] - cur[-1]["end"] > cooldown:
                groups.append({"entity": ent, "units": cur})
                cur = []
            cur.append(u)
        if cur:
            groups.append({"entity": ent, "units": cur})
    return groups


def evaluate_units(
    units: Sequence[dict], task: str, observed_hours: float, cooldown: timedelta
) -> dict[str, Any]:
    """``units``: dicts with label, scenario, instance, entity, start, end, rule_hit_threat,
    rule_hit_any, ml_status, ml_score, ml_hit. T1 uses threat-category rules only (operational
    5xx/latency rules are meant to fire on outages); T2 uses all window rules."""
    spec = TASKS[task]
    rk = "rule_hit_threat" if spec["rule_scope"] == "threat" else "rule_hit_any"
    eligible = [u for u in units if u["label"] in spec["positive"] | spec["negative"]]
    excluded = len(units) - len(eligible)
    y = [1 if u["label"] in spec["positive"] else 0 for u in eligible]
    out: dict[str, Any] = {
        "task": task,
        "task_description": spec["description"],
        "unit": "entity-window",
        "rules_used": "threat-category rules"
        if spec["rule_scope"] == "threat"
        else "all window rules (threat + operational)",
        "units_total": len(units),
        "units_excluded_unknown_label": excluded,
        "label_counts": _counts(u["label"] for u in units),
        "observed_hours": round(observed_hours, 3),
        "methods": {},
    }
    preds = {
        "rules_only": [int(u[rk]) for u in eligible],
        "ml_only": [int(u["ml_hit"]) for u in eligible],
        "hybrid_or": [int(u[rk] or u["ml_hit"]) for u in eligible],
    }
    for m in METHODS:
        bm = binary_metrics(y, preds[m])
        neg = bm["support_negative"]
        bm["fp_per_1000_negative_windows"] = (bm["fp"] * 1000 / neg) if neg else None
        bm["fp_windows_per_observed_hour"] = (bm["fp"] / observed_hours) if observed_hours > 0 else None
        tagged = [dict(u, _pred=p, _y=t) for u, p, t in zip(eligible, preds[m], y, strict=True)]
        groups = group_alerts(tagged, "_pred", cooldown)
        tp_groups = sum(1 for g in groups if any(x["_y"] for x in g["units"]))
        bm["grouped_alerts"] = {
            "total": len(groups),
            "containing_positive_window": tp_groups,
            "without_positive_window": len(groups) - tp_groups,
            "note": "grouped per entity with cooldown; counts are alerts, not attacks",
        }
        bm["per_scenario"] = _per_scenario(eligible, preds[m])
        out["methods"][m] = bm
    scored = [(u, t) for u, t in zip(eligible, y, strict=True) if u["ml_status"] == "SCORED"]
    ys = np.asarray([t for _, t in scored], dtype=int)
    ss = np.asarray([u["ml_score"] for u, _ in scored], dtype=float)
    ap = None
    if len(ys) and 0 < ys.sum() < len(ys):
        ap = float(average_precision_score(ys, ss))
    out["ml_ranking"] = {
        "metric": "average_precision (sklearn.metrics.average_precision_score; step-wise, no interpolation)",
        "value": ap,
        "support_scored": int(len(ys)),
        "support_scored_positive": int(ys.sum()) if len(ys) else 0,
        "abstained_windows": sum(1 for u in eligible if u["ml_status"] != "SCORED"),
        "abstain_policy": "abstained windows count as 'no ML alert' in ml_only and hybrid_or",
        "prevalence_baseline": float(ys.mean()) if len(ys) else None,
    }
    return out


def _counts(it) -> dict[str, int]:
    d: dict[str, int] = defaultdict(int)
    for x in it:
        d[x] += 1
    return dict(d)


def _per_scenario(units: Sequence[dict], preds: Sequence[int]) -> dict[str, Any]:
    by: dict[str, dict[str, Any]] = {}
    inst_hit: dict[tuple[str, str], bool] = {}
    for u, p in zip(units, preds, strict=True):
        sc = u.get("scenario")
        if not sc:
            continue
        d = by.setdefault(sc, {"label": u["label"], "windows": 0, "windows_flagged": 0})
        d["windows"] += 1
        d["windows_flagged"] += int(p)
        key = (sc, u.get("instance") or "")
        inst_hit[key] = inst_hit.get(key, False) or bool(p)
    for (sc, _), hit in inst_hit.items():
        d = by[sc]
        d["instances"] = d.get("instances", 0) + 1
        d["instances_flagged"] = d.get("instances_flagged", 0) + int(hit)
    return by


def window_label(
    domain: str, entity: str, start: datetime, end: datetime, intervals: Sequence[dict], background: str
) -> tuple[str, str | None, str | None]:
    """Label by overlap of [start, end) with labeled intervals for this entity (or '*').
    Returns (label, scenario, instance)."""
    best = (background, None, None)
    best_rank = LABEL_PRECEDENCE.get(background, -1)
    for iv in intervals:
        if iv["domain"] != domain:
            continue
        if iv["entity_key"] != "*" and iv["entity_key"] != entity:
            continue
        if iv["start"] < end and iv["end"] > start:
            rank = LABEL_PRECEDENCE.get(iv["label"], -1)
            if rank > best_rank:
                best = (iv["label"], iv.get("scenario"), iv.get("instance"))
                best_rank = rank
    return best
