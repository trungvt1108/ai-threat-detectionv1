import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
from django.utils import timezone

from ai_threat_detection.sources.follow import follow_once, replay
from ai_threat_detection.sources.ingest import IngestOptions, import_source_file
from ai_threat_detection.sources.models import Event, RejectedRecord, SourceCheckpoint, SourceHealth
from ai_threat_detection.sources.paths import PathNotAllowedError, resolve_source_file, validate_source_root

from .conftest import T0, auth_rec, http_rec, iso, write_ndjson

pytestmark = pytest.mark.django_db


def root(src) -> Path:
    return Path(src.root_path)


def test_reimport_same_batch_is_idempotent_and_identical_lines_are_distinct(make_source):
    src = make_source("auth1", "auth_json")
    same = auth_rec(T0, ip="203.0.113.9", user="bob")
    write_ndjson(root(src) / "a.ndjson", [same, same, same])
    r1 = import_source_file(src, "a.ndjson")
    assert r1.accepted == 3  # three identical failed logins are three events
    r2 = import_source_file(src, "a.ndjson")
    assert r2.accepted == 0 and r2.records_seen == 0  # checkpoint: nothing new
    r3 = import_source_file(src, "a.ndjson", IngestOptions(from_start=True))
    assert r3.accepted == 0 and r3.duplicates == 3  # forced re-read is de-duplicated, not double counted
    assert Event.objects.count() == 3


def test_append_resumes_from_checkpoint(make_source):
    src = make_source()
    p = write_ndjson(root(src) / "a.ndjson", [http_rec(T0), http_rec(T0 + timedelta(seconds=1))])
    import_source_file(src, "a.ndjson")
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(http_rec(T0 + timedelta(seconds=2))) + "\n")
    r = import_source_file(src, "a.ndjson")
    assert r.accepted == 1 and Event.objects.count() == 3


def test_partial_trailing_line_waits_in_follow_mode(make_source):
    src = make_source()
    p = root(src) / "f.ndjson"
    p.write_text(
        json.dumps(http_rec(T0)) + "\n" + '{"timestamp": "2026-05-04T10:00:01Z", "client_ip": "198.51',
        encoding="utf-8",
        newline="\n",
    )
    res = follow_once(src, "f.ndjson")
    assert res["accepted"] == 1
    cp = SourceCheckpoint.objects.get(source=src)
    first_len = len((json.dumps(http_rec(T0)) + "\n").encode())
    assert cp.offset == first_len
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        fh.write('.100.8", "method": "GET", "path": "/", "status": 200}\n')
    res = follow_once(src, "f.ndjson")
    assert res["accepted"] == 1 and Event.objects.count() == 2 and RejectedRecord.objects.count() == 0


def test_follow_rotation_drains_old_file_then_new(make_source):
    src = make_source()
    p = root(src) / "app.ndjson"
    write_ndjson(p, [http_rec(T0, path="/a")])
    follow_once(src, "app.ndjson")
    with open(p, "a", encoding="utf-8", newline="\n") as fh:  # written after last poll, before rotation
        fh.write(json.dumps(http_rec(T0 + timedelta(seconds=1), path="/b")) + "\n")
    os.replace(p, root(src) / "app.ndjson.1")
    write_ndjson(p, [http_rec(T0 + timedelta(seconds=2), path="/c")])
    res = follow_once(src, "app.ndjson")
    paths = sorted(e.fields["path"] for e in Event.objects.all())
    assert paths == ["/a", "/b", "/c"]
    assert "rotated_old_file_drained" in res["notes"]


def test_follow_rotation_without_old_file_is_reported(make_source):
    src = make_source()
    p = root(src) / "app.ndjson"
    write_ndjson(p, [http_rec(T0, path="/a")])
    follow_once(src, "app.ndjson")
    p.unlink()
    write_ndjson(p, [http_rec(T0 + timedelta(seconds=5), path="/new")])
    res = follow_once(src, "app.ndjson")
    assert "rotation_old_file_not_found_possible_data_loss" in res["notes"]


def test_truncate_resets_offset_and_is_noted(make_source):
    src = make_source()
    p = root(src) / "t.ndjson"
    first = http_rec(T0, path="/first")
    write_ndjson(p, [first, http_rec(T0 + timedelta(seconds=1)), http_rec(T0 + timedelta(seconds=2))])
    follow_once(src, "t.ndjson")
    write_ndjson(p, [first])  # copytruncate style: same first line, shorter file
    r = import_source_file(src, "t.ndjson", IngestOptions(final=False))
    assert "truncated_since_checkpoint_reset_to_0" in r.notes


def test_missing_file_and_permission_denied_are_health_states(make_source, monkeypatch):
    src = make_source()
    res = follow_once(src, "nope.ndjson")
    assert res["status"] == "MISSING"
    assert SourceHealth.objects.get(source=src).status == "MISSING"
    write_ndjson(root(src) / "p.ndjson", [http_rec(T0)])
    import ai_threat_detection.sources.follow as follow_mod

    def deny(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(follow_mod, "identify", deny)
    assert follow_once(src, "p.ndjson")["status"] == "PERMISSION_DENIED"
    assert SourceHealth.objects.get(source=src).status == "PERMISSION_DENIED"


def test_restart_after_crash_mid_import_does_not_double_count(make_source, monkeypatch, settings):
    src = make_source()
    recs = [http_rec(T0 + timedelta(seconds=i)) for i in range(50)]
    write_ndjson(root(src) / "c.ndjson", recs)
    import ai_threat_detection.sources.ingest as ing

    calls = {"n": 0}
    orig = ing.Ingestor._flush

    def crashing(self, *a, **k):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("simulated crash")
        return orig(self, *a, **k)

    monkeypatch.setattr(ing.Ingestor, "_flush", crashing)
    with pytest.raises(RuntimeError):
        import_source_file(src, "c.ndjson", IngestOptions(chunk_size=10))
    monkeypatch.setattr(ing.Ingestor, "_flush", orig)
    assert Event.objects.count() == 20  # two committed chunks
    import_source_file(src, "c.ndjson", IngestOptions(chunk_size=10))
    assert Event.objects.count() == 50


def test_json_array_file(make_source):
    src = make_source(file_pattern="*.json")
    p = root(src) / "arr.json"
    p.write_text(
        json.dumps([http_rec(T0), 5, http_rec(T0 + timedelta(seconds=1))]), encoding="utf-8", newline="\n"
    )
    r = import_source_file(src, "arr.json")
    assert r.accepted == 2 and r.reject_reasons == {"not_json_object": 1}


def test_future_timestamp_flagged_and_excluded(make_source):
    src = make_source()
    future = timezone.now() + timedelta(days=2)
    write_ndjson(root(src) / "f.ndjson", [http_rec(future)])
    r = import_source_file(src, "f.ndjson")
    ev = Event.objects.get()
    assert r.future_events == 1 and "future_timestamp" in ev.quality_flags and ev.excluded_from_windows


def test_path_boundaries(make_source, tmp_path):
    src = make_source()
    with pytest.raises(PathNotAllowedError):
        resolve_source_file(src.root_path, "../escape.ndjson", "*.ndjson")
    with pytest.raises(PathNotAllowedError):
        resolve_source_file(src.root_path, str(tmp_path / "abs.ndjson"), "*.ndjson")
    with pytest.raises(PathNotAllowedError):
        resolve_source_file(src.root_path, "a.txt", "*.ndjson")
    with pytest.raises(PathNotAllowedError):
        validate_source_root(str(tmp_path))  # not in ATD_ALLOWED_SOURCE_ROOTS


def test_replay_namespace_is_separate(make_source):
    src = make_source()
    write_ndjson(root(src) / "r.ndjson", [http_rec(T0 + timedelta(seconds=i)) for i in range(5)])
    with pytest.raises(ValueError):
        replay(src, "r.ndjson", "live")
    clocks = []
    replay(src, "r.ndjson", "replay:t1", on_watermark=clocks.append, chunk_size=2)
    assert Event.objects.filter(namespace="replay:t1").count() == 5
    assert Event.objects.filter(namespace="live").count() == 0
    assert clocks == sorted(clocks) and clocks[-1] == T0 + timedelta(seconds=4)


def test_missing_entity_is_stored_but_excluded(make_source):
    src = make_source()
    write_ndjson(
        root(src) / "m.ndjson", [{"timestamp": iso(T0), "path": "/", "status": 200, "method": "GET"}]
    )
    import_source_file(src, "m.ndjson")
    ev = Event.objects.get()
    assert ev.entity_key is None and ev.excluded_from_windows and "missing_entity" in ev.quality_flags
