"""Text log adapters (nginx/Apache combined, sshd syslog), build_dataset, dataset-wide
detection and health rules on dataset import."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from ai_threat_detection.alerts.models import Alert
from ai_threat_detection.experiments.builder import InputSpec, build_dataset
from ai_threat_detection.experiments.datasets import DatasetError, import_dataset, register_dataset
from ai_threat_detection.normalization.pseudonym import Pseudonymizer
from ai_threat_detection.sources.adapters.base import ParseContext
from ai_threat_detection.sources.adapters.registry import get_adapter
from ai_threat_detection.sources.ingest import import_source_file
from ai_threat_detection.sources.models import Event, Source
from ai_threat_detection.sources.paths import PathNotAllowedError

CTX = ParseContext(pseudonymizer=Pseudonymizer(b"t" * 32, scope="test"), assume_timezone="Asia/Ho_Chi_Minh")


def parse(adapter: str, line: str, ctx: ParseContext = CTX):
    a = get_adapter(adapter)
    rec, err = a.decode_line(line.encode(), False)
    assert err is None
    return a.parse(rec, ctx)


def clf(t: datetime, ip="203.0.113.5", req="GET / HTTP/1.1", status=200, size="512", tail=' "-" "ua"'):
    return f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{req}" {status} {size}{tail}'


def sshd(t: datetime, msg: str, prog="sshd[812]", host="web1") -> str:
    return f"{t.isoformat()} {host} {prog}: {msg}"


# ---- http_combined ---------------------------------------------------------------


def test_combined_line_keeps_only_allowlisted_fields():
    o = parse(
        "http_combined",
        '203.0.113.5 - frank [28/Oct/2026:09:00:01 +0700] "GET /admin/accounts/123?token=s3cr3t HTTP/1.1" '
        '404 512 "https://ref.example/" "curl/8.0"',
    )
    ev = o.event
    assert ev is not None and ev.domain == "HTTP"
    assert ev.event_time == datetime(2026, 10, 28, 2, 0, 1, tzinfo=UTC)
    assert ev.fields["method"] == "GET" and ev.fields["status"] == 404 and ev.fields["bytes"] == 512
    assert ev.fields["path"] == "/admin/accounts/{num}" and ev.fields["had_query"] is True
    dumped = json.dumps(ev.fields)
    for secret in ("s3cr3t", "frank", "curl", "ref.example", "HTTP/1.1"):
        assert secret not in dumped
    assert ev.entity_key.startswith("ip_") and "203.0.113.5" not in ev.entity_key
    assert "missing_duration" in ev.quality_flags


def test_combined_dash_bytes_duration_key_and_malformed_requests():
    t = datetime(2026, 1, 5, 8, 0, tzinfo=UTC)
    ev = parse(
        "http_combined", clf(t, req="POST /login HTTP/1.1", status=401, size="-", tail=" rt=0.042")
    ).event
    assert ev.fields["bytes"] == 0 and ev.fields["duration_ms"] == 42.0
    assert "missing_duration" not in ev.quality_flags
    probe = parse("http_combined", clf(t, req="\\x16\\x03\\x01\\x00", status=400)).event
    assert probe.fields["method"] == "OTHER" and probe.fields["path"] is None
    assert "malformed_request_line" in probe.quality_flags
    assert parse("http_combined", "not an access log line").reject_reason == "unrecognized_access_line"
    bad_month = clf(t).replace("/Jan/", "/Foo/")
    assert parse("http_combined", bad_month).reject_reason == "invalid_timestamp"


# ---- auth_syslog -----------------------------------------------------------------


def test_sshd_iso_lines_success_and_failure():
    t = datetime(2026, 10, 28, 9, 0, 1, 123456, tzinfo=UTC)
    f = parse(
        "auth_syslog", sshd(t, "Failed password for invalid user admin from 203.0.113.5 port 52314 ssh2")
    )
    ev = f.event
    assert ev.fields["outcome"] == "FAILURE" and ev.fields["reason"] == "invalid_user"
    assert ev.fields["auth_method"] == "password" and ev.fields["service"] == "sshd"
    assert ev.user_key.startswith("user_") and ev.host_key.startswith("host_")
    assert "admin" not in json.dumps(ev.fields)
    ok = parse(
        "auth_syslog",
        sshd(
            t,
            "Accepted publickey for alice from 2001:db8::7 port 50022 ssh2: ED25519 SHA256:abc",
            "sshd-session[9]",
        ),
    ).event
    assert ok.fields["outcome"] == "SUCCESS" and ok.fields["reason"] is None
    # nanosecond fractions and +HHMM offsets (journalctl short-iso) parse too
    jl = parse(
        "auth_syslog",
        "2026-10-28T16:00:01.123456789+0700 web1 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
    )
    assert jl.event.event_time == datetime(2026, 10, 28, 9, 0, 1, 123456, tzinfo=UTC)


def test_sshd_bsd_timestamp_needs_timezone_and_infers_year():
    ref = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)
    ctx = ParseContext(pseudonymizer=CTX.pseudonymizer, assume_timezone="UTC", reference_time=ref)
    line = "Dec 31 23:59:00 web1 sshd[5]: Failed password for root from 203.0.113.5 port 1 ssh2"
    ev = parse("auth_syslog", line, ctx).event
    assert ev.event_time == datetime(2025, 12, 31, 23, 59, tzinfo=UTC)  # previous year: not in the future
    assert {"tz_assumed", "year_inferred"} <= set(ev.quality_flags)
    no_tz = ParseContext(pseudonymizer=CTX.pseudonymizer, reference_time=ref)
    assert parse("auth_syslog", line, no_tz).reject_reason == "missing_timezone"


def test_sshd_skips_out_of_scope_lines_and_collapses_repeats():
    t = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
    assert parse("auth_syslog", sshd(t, "session opened for user root", "CRON[99]")).skip_reason == "not_sshd"
    assert (
        parse("auth_syslog", sshd(t, "Invalid user admin from 203.0.113.5 port 1")).skip_reason
        == "invalid_user_notice"
    )
    assert (
        parse("auth_syslog", sshd(t, "Connection closed by 203.0.113.5 port 1 [preauth]")).skip_reason
        == "sshd_other_message"
    )
    rep = parse(
        "auth_syslog",
        sshd(t, "message repeated 3 times: [ Failed password for root from 203.0.113.5 port 1 ssh2]"),
    )
    assert (
        rep.event.fields["outcome"] == "FAILURE" and "repeated_message_collapsed" in rep.event.quality_flags
    )
    assert parse("auth_syslog", "garbage").reject_reason == "unrecognized_syslog_line"


# ---- ingest + detection with text sources -------------------------------------------


@pytest.mark.django_db
def test_auth_log_import_counts_skips_separately_and_rules_fire(make_source, seeded_rules):
    from ai_threat_detection.alerts.detection import run_detection

    src = make_source("authlog", "auth_syslog", file_pattern="auth.log*")
    t0 = datetime(2026, 5, 4, 10, 0, tzinfo=UTC)
    lines = [sshd(t0, "pam_unix(cron:session): session opened", "CRON[1]")]
    lines += [
        sshd(
            t0 + timedelta(seconds=5 * i), f"Failed password for root from 203.0.113.66 port {4000 + i} ssh2"
        )
        for i in range(12)
    ]
    lines += [sshd(t0 + timedelta(seconds=70), "Accepted password for root from 203.0.113.66 port 5000 ssh2")]
    lines += [sshd(t0 + timedelta(seconds=80), "Received disconnect from 203.0.113.66 port 5000:11: bye")]
    (Path(src.root_path) / "auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    run = import_source_file(src, "auth.log")
    assert run.accepted == 13 and run.rejected == 0 and run.skipped == 2
    assert run.skip_reasons == {"not_sshd": 1, "sshd_other_message": 1}
    assert run.parse_failure_ratio == 0.0
    run_detection("live", "AUTH", finalize=True)
    alert = Alert.objects.get(domain="AUTH")
    assert "AUTH-001" in alert.rule_ids and "AUTH-003" in alert.rule_ids


def test_register_source_defaults_pattern_by_type(db, inbox):
    root = inbox / "weblogs"
    root.mkdir()
    call_command("register_source", "--name", "nginx-a", "--type", "http_combined", "--root", str(root))
    call_command("register_source", "--name", "json-a", "--type", "http_json", "--root", str(root))
    assert Source.objects.get(name="nginx-a").file_pattern == "*"
    assert Source.objects.get(name="json-a").file_pattern == "*.ndjson"


# ---- build_dataset / dataset import health / dataset detect --------------------------


def _write_access_log(path: Path, days: int, start: datetime, bad_every: int = 0) -> None:
    lines = []
    for d in range(days):
        for i in range(144):  # every 10 min over the whole day
            t = start + timedelta(days=d, minutes=10 * i)
            lines.append(clf(t, ip=f"198.51.100.{i % 5}", req=f"GET /p/{i % 7} HTTP/1.1"))
            if bad_every and i % bad_every == 0:
                lines.append("### corrupted line ###")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


@pytest.mark.django_db
def test_build_dataset_splits_by_day_with_purge_gap_and_labels(inbox, seeded_rules):
    start = datetime(2026, 3, 1, 0, 0, tzinfo=UTC)
    log = inbox / "bd1" / "access.log"
    log.parent.mkdir()
    _write_access_log(log, days=4, start=start)
    labels = inbox / "bd1" / "labels.json"
    labels.write_text(
        json.dumps(
            [
                {
                    "label": "SUSPICIOUS_PATTERN",
                    "domain": "HTTP",
                    "entity": {"kind": "ip", "value": "198.51.100.3"},
                    "start": "2026-03-03T01:00:00+00:00",
                    "end": "2026-03-03T02:00:00+00:00",
                }
            ]
        ),
        encoding="utf-8",
    )
    res = build_dataset(
        "bd1", [InputSpec("HTTP", "http_combined", str(log))], labels_path=str(labels), gap_seconds=600
    )
    assert res["captures"] == 4
    # the 23:50 line of each day lies in the last 600 s -> dropped, not split across captures
    assert res["dropped_in_gap"] == {"HTTP": 4}
    m = json.loads((inbox.parent / "datasets" / "bd1" / "dataset.json").read_text(encoding="utf-8"))
    assert m["sources"] == {"HTTP": {"type": "http_combined"}}
    caps = {c["capture_id"]: c for c in m["captures"]}
    assert list(caps) == ["d20260301T0000", "d20260302T0000", "d20260303T0000", "d20260304T0000"]
    assert caps["d20260301T0000"]["end"] == "2026-03-01T23:50:00+00:00"
    lab3 = json.loads(
        (inbox.parent / "datasets" / "bd1" / "captures" / "d20260303T0000" / "labels.json").read_text()
    )
    assert len(lab3["intervals"]) == 1 and lab3["background_label"] == "UNKNOWN"

    ds = register_dataset("bd1")
    stats = import_dataset(ds)
    assert sum(s["HTTP"]["accepted"] for s in stats.values()) == 4 * 143
    src = Source.objects.get(name="ds-bd1-http")
    assert src.source_type == "http_combined" and src.file_pattern == "*"

    from ai_threat_detection.experiments.service import create_experiment, train_detector
    from ai_threat_detection.features.spec import WindowConfig

    exp = create_experiment(
        ds,
        "bd1-exp",
        "bd1",
        WindowConfig(),
        counts=(2, 1, 1),
        feature_sets={"AUTH": "auth_v1", "HTTP": "http_v1_core"},
    )
    mv = train_detector(exp, "HTTP", train_on_unknown=True)
    assert mv.feature_set == "http_v1_core" and mv.status == "CANDIDATE"

    call_command("detect", "--dataset", "bd1")
    assert Event.objects.filter(namespace__startswith="ds:bd1/").count() == 4 * 143


@pytest.mark.django_db
def test_build_dataset_refuses_outside_roots_and_too_few_captures(inbox, tmp_path):
    outside = tmp_path / "access.log"
    _write_access_log(outside, days=3, start=datetime(2026, 3, 1, tzinfo=UTC))
    with pytest.raises(PathNotAllowedError):
        build_dataset("bd2", [InputSpec("HTTP", "http_combined", str(outside))])
    inside = inbox / "bd3" / "access.log"
    inside.parent.mkdir()
    _write_access_log(inside, days=2, start=datetime(2026, 3, 1, tzinfo=UTC))
    with pytest.raises(DatasetError, match="need >= 3"):
        build_dataset("bd3", [InputSpec("HTTP", "http_combined", str(inside))])
    with pytest.raises(DatasetError):
        build_dataset("bd4", [InputSpec("HTTP", "auth_syslog", str(inside))])
    with pytest.raises(CommandError):
        call_command(
            "build_dataset",
            "--dataset-id",
            "bd5",
            "--http-file",
            str(outside),
            "--http-type",
            "http_combined",
        )


@pytest.mark.django_db
def test_dataset_import_runs_health_rules(inbox, seeded_rules):
    log = inbox / "bd6" / "access.log"
    log.parent.mkdir()
    _write_access_log(log, days=3, start=datetime(2026, 3, 1, tzinfo=UTC), bad_every=5)  # ~17% bad lines
    build_dataset("bd6", [InputSpec("HTTP", "http_combined", str(log))])
    stats = import_dataset(register_dataset("bd6"))
    assert all(s["HTTP"]["health_alerts"] == ["HLTH-001"] for s in stats.values())
    health = Alert.objects.filter(domain="HEALTH", namespace__startswith="ds:bd6/")
    assert health.count() == 3
    a = health.order_by("window_start").first()
    assert a.window_start.date().isoformat() == "2026-03-01"  # event-time span, not import wall clock


@pytest.mark.django_db
def test_sample_logs_detect_after_experiment_finds_both_incidents(inbox, seeded_rules):
    """Regression: an experiment on a dataset must not consume the detection checkpoint."""
    import shutil

    from ai_threat_detection.experiments.models import Dataset
    from ai_threat_detection.experiments.service import create_experiment
    from ai_threat_detection.features.spec import WindowConfig

    pub = Path(__file__).resolve().parents[1] / "fixtures" / "public"
    d = inbox / "samples"
    d.mkdir()
    shutil.copy(pub / "nginx_access_sample.txt", d / "access.log")
    shutil.copy(pub / "auth_sshd_sample.txt", d / "auth.log")
    call_command(
        "build_dataset",
        "--dataset-id", "samples",
        "--http-file", str(d / "access.log"),
        "--http-type", "http_combined",
        "--auth-file", str(d / "auth.log"),
        "--auth-type", "auth_syslog",
        "--capture-hours", "1",
    )  # fmt: skip
    call_command("import_dataset", "--dataset", "samples")
    create_experiment(
        Dataset.objects.get(dataset_id="samples"), "samples-w300", "s", WindowConfig(), counts=(2, 1, 1)
    )
    call_command("detect", "--dataset", "samples")
    got = {
        (a.namespace, a.domain, tuple(sorted(a.rule_ids)))
        for a in Alert.objects.filter(namespace__startswith="ds:samples/")
    }
    assert (
        "ds:samples/d20260302T0100",
        "AUTH",
        ("AUTH-001", "AUTH-003"),
    ) in got  # guessing burst, then success
    assert ("ds:samples/d20260302T0200", "HTTP", ("HTTP-001",)) in got  # path scan
    assert {g[0] for g in got} <= {"ds:samples/d20260302T0100", "ds:samples/d20260302T0200"}
    call_command("detect", "--dataset", "samples")  # idempotent: no duplicate alerts
    assert Alert.objects.filter(namespace__startswith="ds:samples/").count() == len(got)


def test_text_adapters_stay_fast_on_adversarial_64k_lines():
    import time

    n = 65536
    lines = {
        "http_combined": [
            '1 - - [01/Jan/2026:00:00:00 +0000] "' + "\\\\" * (n // 2),
            '1 - - [01/Jan/2026:00:00:00 +0000] "' + "G" * n + '" 200 1' + ' "x"' * 1000,
        ],
        "auth_syslog": [
            "2026-01-01T00:00:00+00:00 h sshd[1]: Failed password for " + "a from " * (n // 7),
            "Jan  1 00:00:00 h sshd[1]: message repeated 2 times: [ " + " for " * (n // 5) + "]",
        ],
    }
    for name, cases in lines.items():
        for line in cases:
            t = time.perf_counter()
            o = parse(name, line)
            assert time.perf_counter() - t < 0.5
            assert o.event is None
