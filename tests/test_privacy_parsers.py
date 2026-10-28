import json
import logging

import pytest

from ai_threat_detection.normalization.privacy import RedactingLogFilter, normalize_path, scrub_text
from ai_threat_detection.normalization.pseudonym import Pseudonymizer
from ai_threat_detection.normalization.timeparse import parse_timestamp
from ai_threat_detection.sources.adapters.base import ParseContext
from ai_threat_detection.sources.adapters.registry import get_adapter
from ai_threat_detection.sources.ingest import import_source_file
from ai_threat_detection.sources.models import Event, RejectedRecord

from .conftest import T0, auth_rec, http_rec, iso, write_ndjson

KEY = bytes(range(32))


def ctx(**kw):
    return ParseContext(pseudonymizer=Pseudonymizer(KEY), **kw)


def test_scrub_text_removes_secrets():
    s = "Authorization: Bearer abcdef123456 token=s3cr3t&x=1 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl a@b.example.com"
    out, kinds = scrub_text(s)
    assert (
        "abcdef123456" not in out
        and "s3cr3t" not in out
        and "eyJhbGci" not in out
        and "a@b.example.com" not in out
    )
    assert {"bearer", "kv_secret", "jwt", "email"} <= set(kinds)


def test_normalize_path_drops_query_and_tokenizes_ids():
    n = normalize_path("https://user:pw@host.example/reset/123/abcdef0123456789abcd?token=SECRET&user=x#frag")
    assert n.path == "/reset/{num}/{hex}"
    assert n.had_query and n.query_param_count == 2
    assert "SECRET" not in n.path and "host" not in n.path
    assert "absolute_url_stripped" in n.flags
    assert normalize_path("/.env").path == "/.env"
    assert normalize_path("/a/<script>alert(1)</script>").path.endswith("{other}")


def test_timestamp_policy():
    assert parse_timestamp("2026-01-01T00:00:00Z").value.tzinfo is not None
    assert parse_timestamp("2026-01-01T00:00:00.123456+0000").value.microsecond == 123456
    naive = parse_timestamp("2026-01-01 08:00:00")
    assert naive.value is None and naive.error == "missing_timezone"
    assumed = parse_timestamp("2026-01-01 08:00:00", "Asia/Ho_Chi_Minh")
    assert assumed.value.hour == 1 and "tz_assumed" in assumed.flags
    assert parse_timestamp(None).error == "missing_timestamp"
    assert parse_timestamp("1999-01-01T00:00:00Z").error == "implausible_timestamp"
    assert parse_timestamp(1767225600).flags == ["epoch_ts"]
    assert parse_timestamp(True).error == "invalid_timestamp"


def test_http_adapter_allowlist_and_redaction():
    rec = http_rec(
        T0,
        path="/login?password=hunter2&next=/x",
        headers={"cookie": "session=abc", "authorization": "Bearer zzz"},
        user_agent="UA",
        body="secret body",
    )
    out = get_adapter("http_json").parse(rec, ctx())
    ev = out.event
    blob = json.dumps(ev.fields)
    for bad in ("hunter2", "session=abc", "Bearer", "secret body", "UA", "198.51.100.7"):
        assert bad not in blob
    assert ev.fields["path"] == "/login" and ev.fields["query_param_count"] == 2
    assert ev.entity_key.startswith("ip_") and len(ev.entity_key) == 19


def test_http_missing_fields_are_missing_not_defaults():
    rec = {"timestamp": iso(T0), "client_ip": "198.51.100.1", "path": "/"}
    ev = get_adapter("http_json").parse(rec, ctx()).event
    assert ev.fields["status"] is None and ev.fields["bytes"] is None and ev.fields["duration_ms"] is None
    assert {"missing_status", "missing_bytes", "missing_duration", "missing_method"} <= set(ev.quality_flags)


def test_auth_outcome_mapping_missing_is_not_success():
    a = get_adapter("auth_json")
    assert a.parse(auth_rec(T0, outcome="success"), ctx()).event.fields["outcome"] == "SUCCESS"
    assert a.parse(auth_rec(T0, outcome="Failed"), ctx()).event.fields["outcome"] == "FAILURE"
    r = auth_rec(T0)
    del r["outcome"]
    ev = a.parse(r, ctx()).event
    assert ev.fields["outcome"] == "MISSING" and "missing_outcome" in ev.quality_flags
    assert a.parse(auth_rec(T0, outcome="weird"), ctx()).event.fields["outcome"] == "UNKNOWN"
    ev = a.parse(auth_rec(T0, password="p4ss", otp="123456", reason="contains spaces & stuff"), ctx()).event
    assert "p4ss" not in json.dumps(ev.fields) and ev.fields["reason"] is None


def test_eve_adapter_alert_flow_and_unsupported():
    a = get_adapter("suricata_eve")
    base = {
        "timestamp": "2026-01-01T00:00:00.000000+0000",
        "flow_id": 123,
        "src_ip": "203.0.113.5",
        "dest_ip": "192.0.2.10",
        "src_port": 5555,
        "dest_port": 80,
        "proto": "TCP",
        "host": "sensor-a",
    }
    al = a.parse(
        {
            **base,
            "event_type": "alert",
            "payload": "QUJD",
            "payload_printable": "ABC",
            "alert": {
                "signature_id": 2100498,
                "signature": "GPL ATTACK_RESPONSE id check returned root",
                "severity": 2,
                "category": "Potentially Bad Traffic",
                "action": "allowed",
            },
        },
        ctx(),
    ).event
    assert al.domain == "EVE_ALERT" and al.fields["upstream_alert"]["signature_id"] == 2100498
    assert "payload" not in al.fields and "QUJD" not in json.dumps(al.fields)
    assert al.fields["correlation_key"] == "sensor-a:123"
    fl = a.parse(
        {
            **base,
            "event_type": "flow",
            "flow": {"pkts_toserver": 3, "bytes_toserver": 200, "state": "closed", "alerted": False},
        },
        ctx(),
    ).event
    assert fl.domain == "EVE_FLOW" and fl.fields["flow"]["pkts_toserver"] == 3
    assert a.parse({**base, "event_type": "dns"}, ctx()).reject_reason == "unsupported_event_type"
    assert a.parse({**base, "event_type": "alert"}, ctx()).reject_reason == "alert_object_missing"


def test_pseudonym_stable_and_scoped():
    p1, p2 = Pseudonymizer(KEY, "global"), Pseudonymizer(KEY, "other")
    assert p1.pseudonym("ip", "198.51.100.1") == p1.pseudonym("ip", " 198.51.100.1 ")
    assert p1.pseudonym("ip", "198.51.100.1") != p2.pseudonym("ip", "198.51.100.1")
    assert p1.pseudonym("user", "Alice") == p1.pseudonym("user", "alice")
    assert Pseudonymizer(bytes(32)).pseudonym("ip", "198.51.100.1") != p1.pseudonym("ip", "198.51.100.1")


@pytest.mark.django_db
def test_invalid_lines_never_stored_or_logged_raw(make_source, caplog):
    src = make_source()
    secret_line = '{"timestamp": "2026-05-04T10:00:00Z", "password": "TOPSECRET-123", broken'
    write_ndjson(src_root(src) / "a.ndjson", [http_rec(T0)], raw_lines=[secret_line, "[1,2]", "x" * 70000])
    caplog.set_level(logging.DEBUG)
    run = import_source_file(src, "a.ndjson")
    assert run.accepted == 1 and run.rejected == 3
    assert run.reject_reasons == {"invalid_json": 1, "not_json_object": 1, "oversized_line": 1}
    rej = RejectedRecord.objects.filter(source=src)
    assert all(r.preview == "" for r in rej)
    assert "TOPSECRET" not in caplog.text
    assert not any("TOPSECRET" in json.dumps(e.fields) for e in Event.objects.all())


@pytest.mark.django_db
def test_stored_events_contain_no_secrets_end_to_end(make_source):
    src = make_source()
    write_ndjson(
        src_root(src) / "a.ndjson",
        [
            http_rec(T0, path="/reset?token=abcdef0123456789", headers={"cookie": "sid=XYZSESSION"}),
            http_rec(T0, path="/x", request_headers={"authorization": "Basic dXNlcjpwYXNz"}),
        ],
    )
    import_source_file(src, "a.ndjson")
    dump = json.dumps(list(Event.objects.values("fields", "quality_flags", "entity_key")))
    for bad in ("abcdef0123456789", "XYZSESSION", "dXNlcjpwYXNz", "198.51.100.7"):
        assert bad not in dump


def test_redacting_log_filter():
    rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed with token=%s", ("abcd1234",), None)
    RedactingLogFilter().filter(rec)
    assert "abcd1234" not in rec.getMessage()


@pytest.mark.django_db
def test_naive_timestamp_uses_declared_assumption(make_source):
    src = make_source(assume_timezone="Europe/Berlin")
    write_ndjson(
        src_root(src) / "a.ndjson",
        [
            {
                "timestamp": "2026-05-04 12:00:00",
                "client_ip": "198.51.100.3",
                "path": "/",
                "status": 200,
                "method": "GET",
            }
        ],
    )
    run = import_source_file(src, "a.ndjson")
    ev = Event.objects.get()
    assert run.accepted == 1 and "tz_assumed" in ev.quality_flags and ev.event_time.hour == 10


def src_root(src):
    from pathlib import Path

    return Path(src.root_path)
