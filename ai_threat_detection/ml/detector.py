"""IsolationForest anomaly detector over explicit window features.

Score semantics
---------------
scikit-learn's ``IsolationForest.score_samples`` returns the *opposite* of the
anomaly score from the original paper: lower = more abnormal, values in [-1, 0).
We store ``anomaly_score = -score_samples(X)`` so that higher = more anomalous
(range (0, 1]). This is a ranking score, not a probability of attack, and
``contamination`` is not a prior on malicious traffic (we keep the default
'auto' and never use ``predict()``; decisions use our own validated threshold).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score
from threadpoolctl import threadpool_limits

from ai_threat_detection.features.compute import ml_eligibility, transform_row
from ai_threat_detection.features.spec import FeatureSet, WindowConfig

SCORE_TRANSFORM = "anomaly_score = -IsolationForest.score_samples(X)  (higher = more anomalous)"
HYPERPARAM_GRID: tuple[dict[str, Any], ...] = (
    {"n_estimators": 100, "max_samples": 256, "max_features": 1.0},
    {"n_estimators": 300, "max_samples": 256, "max_features": 1.0},
    {"n_estimators": 300, "max_samples": 512, "max_features": 1.0},
    {"n_estimators": 300, "max_samples": 256, "max_features": 0.75},
)
BASELINE_QUANTILES = (0.05, 0.25, 0.5, 0.75, 0.95, 0.99)


@dataclass
class Matrix:
    X: np.ndarray
    eligible_idx: list[int]
    abstain: dict[int, str]


def build_matrix(fs: FeatureSet, windows: Sequence[Any], cfg: WindowConfig) -> Matrix:
    """``windows`` need ``.features``, ``.coverage``, ``.event_count``. Only the
    feature-set allowlist is read; any other attribute (labels, capture ids,
    entity keys) is ignored by construction."""
    rows: list[list[float]] = []
    idx: list[int] = []
    abstain: dict[int, str] = {}
    for i, w in enumerate(windows):
        reason = ml_eligibility(fs, w.features, w.coverage, w.event_count, cfg)
        if reason:
            abstain[i] = reason
            continue
        rows.append(transform_row(fs, w.features))
        idx.append(i)
    X = np.asarray(rows, dtype=np.float64).reshape(len(rows), len(fs.features))
    return Matrix(X=X, eligible_idx=idx, abstain=abstain)


def fit_iforest(
    X: np.ndarray, params: dict[str, Any], random_state: int, n_jobs: int
) -> tuple[IsolationForest, float]:
    if X.shape[0] < 20:
        raise ValueError("need at least 20 eligible training windows")
    p = dict(params)
    if isinstance(p.get("max_samples"), int):
        p["max_samples"] = min(p["max_samples"], X.shape[0])
    model = IsolationForest(
        contamination="auto", bootstrap=False, random_state=random_state, n_jobs=n_jobs, **p
    )
    t0 = time.perf_counter()
    with threadpool_limits(limits=n_jobs):
        model.fit(X)
    return model, time.perf_counter() - t0


def anomaly_scores(model: IsolationForest, X: np.ndarray, n_jobs: int = 1) -> np.ndarray:
    if X.shape[0] == 0:
        return np.zeros(0)
    with threadpool_limits(limits=n_jobs):
        return -model.score_samples(X)


def safe_average_precision(y: np.ndarray, scores: np.ndarray) -> float | None:
    if len(y) == 0 or y.sum() == 0 or y.sum() == len(y):
        return None
    return float(average_precision_score(y, scores))


def select_threshold(
    scores: np.ndarray, y: np.ndarray | None, target_fpr: float = 0.01
) -> tuple[float, dict]:
    """Pre-declared rule (docs/EVALUATION_PROTOCOL.md):
    * validation has both classes -> threshold maximizing F1 on validation;
      ties -> the higher threshold (fewer alerts).
    * otherwise -> (1 - target_fpr) quantile of validation scores (all treated as benign reference).
    """
    if len(scores) == 0:
        raise ValueError("no validation scores")
    if y is not None and 0 < int(y.sum()) < len(y):
        order = np.argsort(-scores, kind="mergesort")
        s_sorted = scores[order]
        y_sorted = y[order]
        tp = np.cumsum(y_sorted)
        fp = np.cumsum(1 - y_sorted)
        pos = y.sum()
        best: tuple[float, float, int] = (-1.0, float(s_sorted[0]), 0)
        # Only evaluate at the last index of each distinct score (ties predicted together).
        distinct_last = np.r_[np.nonzero(np.diff(s_sorted))[0], len(s_sorted) - 1]
        for k in distinct_last:
            precision = tp[k] / (tp[k] + fp[k])
            recall = tp[k] / pos
            f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
            if f1 > best[0] + 1e-12:
                best = (f1, float(s_sorted[k]), int(k))
        return best[1], {
            "criterion": "max_f1_validation",
            "validation_f1": best[0],
            "tie_break": "higher_threshold",
        }
    q = float(np.quantile(scores, 1 - target_fpr))
    return q, {
        "criterion": f"validation_quantile_{1 - target_fpr:.3f}",
        "note": "validation lacked both classes",
    }


def baseline_stats(fs: FeatureSet, feature_dicts: Sequence[dict]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name in fs.features:
        vals = np.asarray([float(d[name]) for d in feature_dicts if d.get(name) is not None], dtype=float)
        if len(vals) == 0:
            continue
        qs = np.quantile(vals, BASELINE_QUANTILES)
        out[name] = {f"q{int(q * 100):02d}": float(v) for q, v in zip(BASELINE_QUANTILES, qs, strict=True)}
        out[name]["n"] = int(len(vals))
        # Drift reference: unique decile edges + train proportions per bin (PSI on later data).
        edges = np.unique(np.quantile(vals, np.linspace(0, 1, 11)))
        inner = edges[1:-1]
        counts = np.bincount(np.searchsorted(inner, vals, side="right"), minlength=len(inner) + 1)
        out[name]["bin_edges"] = [float(v) for v in inner]
        out[name]["bin_props"] = [float(c) / len(vals) for c in counts]
    return out


def psi(bin_edges: Sequence[float], expected_props: Sequence[float], values: Sequence[float]) -> float | None:
    """Population stability index of ``values`` against train bins (eps-smoothed)."""
    vals = np.asarray(values, dtype=float)
    if len(vals) == 0:
        return None
    counts = np.bincount(
        np.searchsorted(np.asarray(bin_edges), vals, side="right"), minlength=len(expected_props)
    )
    actual = counts / len(vals)
    exp = np.asarray(expected_props, dtype=float)
    eps = 1e-4
    a = np.clip(actual, eps, None)
    e = np.clip(exp, eps, None)
    return float(np.sum((a - e) * np.log(a / e)))


def reference_quantiles(train_scores: np.ndarray) -> list[float]:
    return [float(v) for v in np.quantile(train_scores, np.linspace(0, 1, 101))]


def score_percentile(score: float, ref: Sequence[float]) -> float:
    """Percentile of ``score`` within the train reference distribution (0-100).
    Not a probability of attack."""
    arr = np.asarray(ref)
    return float(np.searchsorted(arr, score, side="right") - 1) if len(arr) else float("nan")


def deviations(
    fs: FeatureSet, features: dict, baseline: dict[str, dict[str, float]], top: int = 5
) -> list[dict]:
    """Observed value vs train-baseline median/IQR. Descriptive deviation only —
    NOT a model attribution (IsolationForest gives no per-feature contributions)."""
    out = []
    for name in fs.features:
        b = baseline.get(name)
        v = features.get(name)
        if b is None or v is None:
            continue
        iqr = b["q75"] - b["q25"]
        spread = b["q99"] - b["q05"]
        if iqr > 0:
            scale, basis = iqr, "IQR"
        elif spread > 0:
            scale, basis = spread, "p05-p99 (IQR = 0)"
        else:
            scale, basis = None, "baseline constant"
        dev = round((float(v) - b["q50"]) / scale, 2) if scale else None
        out.append(
            {
                "feature": name,
                "observed": v,
                "baseline_median": b["q50"],
                "baseline_p95": b["q95"],
                "baseline_p99": b["q99"],
                "robust_deviation": dev,
                "scale_basis": basis,
                "above_p99": float(v) > b["q99"],
            }
        )
    # Sort: features above train p99 first, then by size of the (defined) deviation.
    out.sort(key=lambda d: (d["above_p99"], abs(d["robust_deviation"] or 0.0)), reverse=True)
    return out[:top]


def choose_hyperparams(
    X_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray | None, random_state: int, n_jobs: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Small fixed grid; selection by validation average precision (task T1).
    Falls back to the first grid entry if validation AP is undefined."""
    trials: list[dict[str, Any]] = []
    for params in HYPERPARAM_GRID:
        model, fit_s = fit_iforest(X_train, params, random_state, n_jobs)
        ap = (
            safe_average_precision(y_val, anomaly_scores(model, X_val, n_jobs)) if y_val is not None else None
        )
        trials.append({"params": params, "validation_ap": ap, "fit_seconds": round(fit_s, 4)})
    scored = [t for t in trials if t["validation_ap"] is not None]
    if not scored:
        return dict(HYPERPARAM_GRID[0]), trials
    best = max(scored, key=lambda t: (t["validation_ap"], -t["params"]["n_estimators"]))
    return dict(best["params"]), trials
