"""Event-time window builder over stored events (single implementation for
experiments, replay and live detection).

* Windows are aligned to the stride from the Unix epoch (UTC), half-open [start, end).
* A window is closed only when ``end <= watermark - allowed_lateness`` (or when the
  caller finalizes a finished capture). Features therefore only use events that
  had arrived by the time a prediction could be made (``available_at``).
* Detection progress is persisted in ``DetectionCheckpoint``; events that arrive
  for an already-closed range are flagged ``late_after_window_close`` at ingest and
  never rewrite historical windows.
* Experiments build windows with ``track=False``: they reuse/insert the same
  deterministic windows but do not advance the detection checkpoint, so running
  detection on a dataset after an experiment still evaluates every window.
* Memory is bounded by one window's events (capped by ATD_MAX_EVENTS_PER_WINDOW).
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from django.db import transaction

from ai_threat_detection.conf import get_config
from ai_threat_detection.sources.models import Event

from .compute import compute_window, first_window_start_containing
from .models import DetectionCheckpoint, FeatureWindow
from .spec import ML_DOMAINS, WindowConfig

EVENT_FIELDS = ("event_id", "event_time", "entity_key", "user_key", "host_key", "fields", "capture_id")
SAMPLE_EVENTS = 25


def _events_qs(namespace: str, domain: str):
    return Event.objects.filter(namespace=namespace, domain=domain, excluded_from_windows=False)


def event_watermark(namespace: str, domain: str) -> datetime | None:
    return _events_qs(namespace, domain).order_by("-event_time").values_list("event_time", flat=True).first()


def build_windows(
    namespace: str,
    domain: str,
    cfg: WindowConfig,
    watermark: datetime | None = None,
    finalize: bool = False,
    ctx=None,
    track: bool = True,
) -> list[FeatureWindow]:
    if domain not in ML_DOMAINS:
        raise ValueError(f"No window features defined for domain {domain} (UPSTREAM_ONLY)")
    cap = get_config().max_events_per_window
    cfg_hash = cfg.config_hash()
    cp: DetectionCheckpoint | None = None
    if track:
        cp, _ = DetectionCheckpoint.objects.get_or_create(
            namespace=namespace, domain=domain, cfg_hash=cfg_hash, defaults={"window_config": cfg.to_dict()}
        )
    processed_until = cp.processed_until if cp is not None else None
    qs = _events_qs(namespace, domain)
    if watermark is None:
        watermark = event_watermark(namespace, domain)
    if watermark is None:
        return []
    size = timedelta(seconds=cfg.size_s)
    stride = timedelta(seconds=cfg.stride_s)
    close_limit = None if finalize else watermark - timedelta(seconds=cfg.allowed_lateness_s)

    if processed_until is None:
        first_t = qs.order_by("event_time").values_list("event_time", flat=True).first()
        if first_t is None:
            return []
        ws = first_window_start_containing(first_t, cfg)
    else:
        ws = processed_until
    start_ws = ws

    created_keys: list[tuple[str, datetime]] = []
    while True:
        if ctx is not None:
            ctx.check()
        if close_limit is not None and ws + size > close_limit:
            break
        rows = list(
            qs.filter(event_time__gte=ws, event_time__lt=ws + size)
            .order_by("event_time", "event_id")
            .only(*EVENT_FIELDS)[: cap + 1]
        )
        if not rows:
            nxt = (
                qs.filter(event_time__gte=ws)
                .order_by("event_time")
                .values_list("event_time", flat=True)
                .first()
            )
            if nxt is None:
                if close_limit is not None:
                    # Every window ending before the close limit is known to be empty.
                    last_start = math.floor((close_limit - size).timestamp() / cfg.stride_s) * cfg.stride_s
                    ws = max(ws, datetime.fromtimestamp(last_start, tz=UTC) + stride)
                break
            ws = max(ws + stride, first_window_start_containing(nxt, cfg))
            continue
        overflow = len(rows) > cap
        rows = rows[:cap]
        by_entity: dict[str, list[Event]] = defaultdict(list)
        for ev in rows:
            by_entity[ev.entity_key].append(ev)
        batch = []
        we = ws + size
        avail = we + timedelta(seconds=cfg.allowed_lateness_s)
        for entity, evs in sorted(by_entity.items()):
            feats, cov, flags = compute_window(domain, evs, cfg)
            if overflow:
                flags.append("window_event_cap_reached")
            captures = {e.capture_id for e in evs if e.capture_id}
            batch.append(
                FeatureWindow(
                    namespace=namespace,
                    domain=domain,
                    cfg_hash=cfg_hash,
                    entity_key=entity,
                    window_start=ws,
                    window_end=we,
                    available_at=avail,
                    event_count=len(evs),
                    features=feats,
                    coverage=cov,
                    quality_flags=flags,
                    capture_id=captures.pop() if len(captures) == 1 else None,
                    sample_event_ids=[e.event_id for e in evs[:SAMPLE_EVENTS]],
                )
            )
        ws_next = ws + stride
        with transaction.atomic():
            FeatureWindow.objects.bulk_create(batch, ignore_conflicts=True)
            if cp is not None:
                cp.windows_built += len(batch)
                DetectionCheckpoint.objects.filter(pk=cp.pk).update(
                    processed_until=ws_next, windows_built=cp.windows_built
                )
        created_keys.extend((w.entity_key, w.window_start) for w in batch)
        ws = ws_next
    if ws != start_ws and cp is not None:
        DetectionCheckpoint.objects.filter(pk=cp.pk).update(processed_until=ws)
    if not created_keys:
        return []
    keys = set(created_keys)
    stored = FeatureWindow.objects.filter(
        namespace=namespace, domain=domain, cfg_hash=cfg_hash, window_start__gte=start_ws, window_start__lt=ws
    ).order_by("window_start", "entity_key")
    return [w for w in stored if (w.entity_key, w.window_start) in keys]
