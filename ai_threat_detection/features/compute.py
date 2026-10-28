"""Pure feature computation shared by training, evaluation, replay and live detection.

Input: events of ONE entity inside ONE window (already restricted to the window
interval), ordered by (event_time, event_id). Output: computed values, coverage
fractions and quality flags. Values that cannot be computed are ``None`` (never
0 or "benign"); coverage tells the ML layer whether to abstain.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np

from .spec import COMPUTED_FEATURES, FeatureSet, WindowConfig


def floor_time(t: datetime, step_s: int) -> datetime:
    ts = int(t.timestamp())
    return datetime.fromtimestamp(ts - (ts % step_s), tz=UTC)


def window_starts_containing(t: datetime, cfg: WindowConfig) -> list[datetime]:
    """All window starts s (aligned to stride from epoch) with s <= t < s + size."""
    ts = t.timestamp()
    first = math.floor((ts - cfg.size_s) / cfg.stride_s) * cfg.stride_s + cfg.stride_s
    out = []
    s = first
    while s <= ts:
        if s + cfg.size_s > ts:
            out.append(datetime.fromtimestamp(s, tz=UTC))
        s += cfg.stride_s
    return out


def first_window_start_containing(t: datetime, cfg: WindowConfig) -> datetime:
    return window_starts_containing(t, cfg)[0]


def window_end(start: datetime, cfg: WindowConfig) -> datetime:
    return start + timedelta(seconds=cfg.size_s)


def _ratio(n: int, d: int) -> float | None:
    return (n / d) if d else None


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    return float(np.percentile(np.asarray(values, dtype=float), q))


def compute_auth(events: Sequence[Any], cfg: WindowConfig) -> tuple[dict, dict, list[str]]:
    n = len(events)
    outcomes = [e.fields.get("outcome") for e in events]
    failures = sum(1 for o in outcomes if o == "FAILURE")
    successes = sum(1 for o in outcomes if o == "SUCCESS")
    unknown = n - failures - successes
    users = {e.user_key for e in events if e.user_key}
    failed_users = {e.user_key for e in events if e.user_key and e.fields.get("outcome") == "FAILURE"}
    services = {e.fields.get("service") for e in events if e.fields.get("service")}
    hosts = {e.host_key for e in events if e.host_key}
    per_user_fail: Counter[str] = Counter(
        e.user_key for e in events if e.user_key and e.fields.get("outcome") == "FAILURE"
    )
    # success for user u preceded (within the window, in time order) by >= 3 failures from this entity
    consecutive: dict[str | None, int] = defaultdict(int)
    saf = 0
    for e in events:
        o = e.fields.get("outcome")
        if o == "FAILURE":
            consecutive[e.user_key] += 1
        elif o == "SUCCESS":
            if consecutive[e.user_key] >= 3:
                saf += 1
            consecutive[e.user_key] = 0
    known = failures + successes
    feats = {
        "attempts": n,
        "failures": failures,
        "successes": successes,
        "unknown_outcomes": unknown,
        "failure_ratio": _ratio(failures, known),
        "distinct_users": len(users),
        "distinct_failed_users": len(failed_users),
        "distinct_services": len(services),
        "distinct_hosts": len(hosts),
        "max_failures_single_user": max(per_user_fail.values()) if per_user_fail else 0,
        "success_after_3_failures": saf,
        "attempts_per_min": n / (cfg.size_s / 60.0),
    }
    coverage = {
        "outcome": _ratio(known, n) or 0.0,
        "user": _ratio(sum(1 for e in events if e.user_key), n) or 0.0,
        "service": _ratio(sum(1 for e in events if e.fields.get("service")), n) or 0.0,
    }
    flags = []
    if unknown:
        flags.append("outcome_missing_or_unknown")
    return feats, coverage, flags


def compute_http(events: Sequence[Any], cfg: WindowConfig) -> tuple[dict, dict, list[str]]:
    n = len(events)
    statuses = [e.fields.get("status") for e in events if e.fields.get("status") is not None]
    sk = len(statuses)
    c2 = sum(1 for s in statuses if 200 <= s < 300)
    c3 = sum(1 for s in statuses if 300 <= s < 400)
    c4 = sum(1 for s in statuses if 400 <= s < 500)
    c404 = sum(1 for s in statuses if s == 404)
    c5 = sum(1 for s in statuses if 500 <= s < 600)
    paths = {e.fields.get("path") for e in events if e.fields.get("path")}
    methods = [e.fields.get("method") for e in events if e.fields.get("method")]
    mk = len(methods)
    nbytes = [float(e.fields["bytes"]) for e in events if e.fields.get("bytes") is not None]
    lat = [float(e.fields["duration_ms"]) for e in events if e.fields.get("duration_ms") is not None]
    feats = {
        "requests": n,
        "status_known": sk,
        "count_2xx": c2,
        "count_3xx": c3,
        "count_4xx": c4,
        "count_404": c404,
        "count_5xx": c5,
        "ratio_4xx": _ratio(c4, sk),
        "ratio_404": _ratio(c404, sk),
        "ratio_5xx": _ratio(c5, sk),
        "distinct_paths": len(paths),
        "distinct_path_ratio": _ratio(len(paths), n),
        "method_get_ratio": _ratio(sum(1 for m in methods if m in ("GET", "HEAD")), mk),
        "method_post_ratio": _ratio(sum(1 for m in methods if m == "POST"), mk),
        "method_other_ratio": _ratio(sum(1 for m in methods if m not in ("GET", "HEAD", "POST")), mk),
        "bytes_median": _pct(nbytes, 50),
        "bytes_p95": _pct(nbytes, 95),
        "latency_median_ms": _pct(lat, 50),
        "latency_p95_ms": _pct(lat, 95),
        "requests_per_min": n / (cfg.size_s / 60.0),
    }
    coverage = {
        "status": _ratio(sk, n) or 0.0,
        "method": _ratio(mk, n) or 0.0,
        "path": _ratio(sum(1 for e in events if e.fields.get("path")), n) or 0.0,
        "bytes": _ratio(len(nbytes), n) or 0.0,
        "duration": _ratio(len(lat), n) or 0.0,
    }
    flags = [f"low_coverage_{k}" for k, v in coverage.items() if v < 0.8]
    return feats, coverage, flags


COMPUTERS = {"AUTH": compute_auth, "HTTP": compute_http}


def compute_window(domain: str, events: Sequence[Any], cfg: WindowConfig) -> tuple[dict, dict, list[str]]:
    feats, cov, flags = COMPUTERS[domain](events, cfg)
    if set(feats) != set(COMPUTED_FEATURES[domain]):
        raise RuntimeError("computed features drifted from spec")
    return feats, cov, flags


def ml_eligibility(
    fs: FeatureSet, features: dict, coverage: dict, event_count: int, cfg: WindowConfig
) -> str | None:
    """None if the window can be scored by a model of feature set ``fs``; otherwise a reason."""
    if event_count < cfg.min_events:
        return "below_min_events"
    for key, minimum in fs.required_coverage.items():
        if coverage.get(key, 0.0) < minimum:
            return f"insufficient_coverage:{key}"
    for name in fs.features:
        if features.get(name) is None:
            return f"missing_feature:{name}"
    return None


def transform_row(fs: FeatureSet, features: dict) -> list[float]:
    """Stateless transforms (no learned parameters), identical for train and inference."""
    row = []
    for name in fs.features:
        v = float(features[name])
        t = fs.transforms.get(name, "identity")
        if t == "log1p":
            row.append(math.log1p(max(v, 0.0)))
        elif t == "identity":
            row.append(v)
        else:  # pragma: no cover - guarded by spec tests
            raise ValueError(f"unknown transform {t}")
    return row
