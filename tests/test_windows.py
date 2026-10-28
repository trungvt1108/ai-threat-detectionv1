from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ai_threat_detection.features.builder import build_windows
from ai_threat_detection.features.compute import compute_auth, window_starts_containing
from ai_threat_detection.features.models import DetectionCheckpoint, FeatureWindow
from ai_threat_detection.features.spec import WindowConfig
from ai_threat_detection.sources.ingest import IngestOptions, import_source_file
from ai_threat_detection.sources.models import Event

from .conftest import T0, auth_rec, http_rec, window_cfg, write_ndjson


def test_window_boundaries_half_open_tumbling_and_sliding():
    tumble = WindowConfig(size_s=60, stride_s=60)
    t = datetime(2026, 1, 1, 0, 1, 0, tzinfo=UTC)
    assert window_starts_containing(t, tumble) == [t]  # exactly on boundary belongs to the next window
    assert window_starts_containing(t - timedelta(microseconds=1), tumble) == [t - timedelta(seconds=60)]
    slide = WindowConfig(size_s=60, stride_s=20)
    starts = window_starts_containing(datetime(2026, 1, 1, 0, 1, 5, tzinfo=UTC), slide)
    assert [s.second for s in starts] == [20, 40, 0] and len(starts) == 3
    with pytest.raises(ValueError):
        WindowConfig(size_s=60, stride_s=45)


def test_config_hash_changes_with_config():
    assert WindowConfig(300, 300).config_hash() != WindowConfig(10, 10).config_hash()


class E:
    def __init__(self, outcome, user, t, service="webapp"):
        self.fields = {"outcome": outcome, "service": service}
        self.user_key = user
        self.host_key = None
        self.event_time = t


def test_auth_features_and_missingness():
    evs = [
        E("FAILURE", "u1", 0),
        E("FAILURE", "u1", 1),
        E("FAILURE", "u1", 2),
        E("SUCCESS", "u1", 3),
        E("MISSING", "u2", 4),
    ]
    f, cov, flags = compute_auth(evs, WindowConfig(60, 60))
    assert f["failures"] == 3 and f["successes"] == 1 and f["unknown_outcomes"] == 1
    assert f["failure_ratio"] == 0.75  # missing outcome excluded from the ratio, not counted as success
    assert f["success_after_3_failures"] == 1 and cov["outcome"] == 0.8
    f2, cov2, _ = compute_auth([E("MISSING", "u1", 0)], WindowConfig(60, 60))
    assert f2["failure_ratio"] is None and cov2["outcome"] == 0.0


def _import(src, recs, name="w.ndjson", **opts):
    write_ndjson(Path(src.root_path) / name, recs)
    return import_source_file(src, name, IngestOptions(**opts))


@pytest.mark.django_db
def test_watermark_closes_only_complete_windows_and_late_events_flagged(make_source):
    src = make_source("a", "auth_json")
    cfg = window_cfg(60, lateness=10)
    _import(src, [auth_rec(T0 + timedelta(seconds=s)) for s in (1, 30, 61, 75)], "1.ndjson")
    ws = build_windows("live", "AUTH", cfg)  # watermark = 75s -> close limit 65s -> only [0,60) closes
    assert [(w.window_start, w.event_count) for w in ws] == [(T0, 2)]
    # an event for the closed window arrives late
    r = _import(
        src, [auth_rec(T0 + timedelta(seconds=20)), auth_rec(T0 + timedelta(seconds=140))], "2.ndjson"
    )
    assert r.late_events == 1
    late = next(e for e in Event.objects.all() if "late_after_window_close" in e.quality_flags)
    assert late.excluded_from_windows
    ws2 = build_windows("live", "AUTH", cfg)
    assert [(w.window_start, w.event_count) for w in ws2] == [(T0 + timedelta(seconds=60), 2)]
    first = FeatureWindow.objects.get(window_start=T0)
    assert first.event_count == 2  # historical window not rewritten


@pytest.mark.django_db
def test_build_is_deterministic_and_idempotent(make_source):
    src = make_source()
    recs = [http_rec(T0 + timedelta(seconds=s), ip=f"198.51.100.{s % 3}") for s in range(0, 300, 7)]
    _import(src, recs)
    cfg = window_cfg(60)
    a = build_windows("live", "HTTP", cfg, finalize=True)
    assert build_windows("live", "HTTP", cfg, finalize=True) == []  # nothing new
    snap = [(w.entity_key, w.window_start, w.features) for w in a]
    FeatureWindow.objects.all().delete()
    DetectionCheckpoint.objects.all().delete()
    b = build_windows("live", "HTTP", cfg, finalize=True)
    assert snap == [(w.entity_key, w.window_start, w.features) for w in b]


@pytest.mark.django_db
def test_window_event_cap_is_flagged(make_source, monkeypatch):
    from ai_threat_detection import conf

    src = make_source()
    _import(src, [http_rec(T0 + timedelta(milliseconds=10 * i)) for i in range(150)])
    cfg = conf.get_config()
    monkeypatch.setattr(
        conf, "get_config", lambda: type(cfg)(**{**cfg.__dict__, "max_events_per_window": 100})
    )
    import ai_threat_detection.features.builder as b

    monkeypatch.setattr(b, "get_config", conf.get_config)
    ws = build_windows("live", "HTTP", window_cfg(60), finalize=True)
    assert ws[0].event_count == 100 and "window_event_cap_reached" in ws[0].quality_flags


@pytest.mark.django_db
def test_incremental_replay_equals_batch(make_source, seeded_rules):
    """Replay with incremental watermarks yields the same closed windows as a finalized batch build."""
    from ai_threat_detection.sources.follow import replay

    src = make_source()
    recs = [
        http_rec(T0 + timedelta(seconds=s), ip=f"198.51.100.{s % 4}", status=404 if s % 5 == 0 else 200)
        for s in range(0, 600, 3)
    ]
    write_ndjson(Path(src.root_path) / "r.ndjson", recs)
    cfg = window_cfg(60, lateness=5)
    replay(
        src,
        "r.ndjson",
        "replay:x",
        on_watermark=lambda clock: build_windows("replay:x", "HTTP", cfg, watermark=clock),
        chunk_size=17,
    )
    build_windows("replay:x", "HTTP", cfg, finalize=True)
    import_source_file(src, "r.ndjson", IngestOptions(namespace="batch"))
    build_windows("batch", "HTTP", cfg, finalize=True)
    rep = {
        (w.entity_key, w.window_start): w.features for w in FeatureWindow.objects.filter(namespace="replay:x")
    }
    bat = {
        (w.entity_key, w.window_start): w.features for w in FeatureWindow.objects.filter(namespace="batch")
    }
    assert rep == bat and len(rep) > 20
