from pathlib import Path

import pytest
from django.test import Client

from ai_threat_detection.alerts.detection import run_detection
from ai_threat_detection.alerts.models import Alert
from ai_threat_detection.sources.ingest import import_source_file
from ai_threat_detection.worker.models import Job

from .conftest import T0, auth_rec, http_rec, write_ndjson

pytestmark = pytest.mark.django_db
PW = "x-test-password-123"

PAGES = [
    "/",
    "/alerts/",
    "/sources/",
    "/datasets/",
    "/jobs/",
    "/models/",
    "/experiments/",
    "/drift/",
    "/reports/",
    "/settings/",
    "/notifications/",
]


def login(role_user) -> Client:
    c = Client()
    assert c.login(username=role_user.username, password=PW)
    return c


def test_login_required_everywhere():
    c = Client()
    for p in PAGES + ["/audit/", "/jobs/status.json"]:
        r = c.get(p)
        assert r.status_code == 302 and "/login/" in r["Location"], p


def test_viewer_can_read_all_pages_with_security_headers(users, seeded_rules):
    c = login(users["viewer"])
    for p in PAGES:
        r = c.get(p)
        assert r.status_code == 200, p
        assert "script-src 'self'" in r["Content-Security-Policy"]
        assert r["X-Frame-Options"] == "DENY"
        assert r["Cache-Control"] == "no-store"
    assert c.get("/audit/").status_code == 403  # admin only


def test_user_without_role_is_denied(users):
    c = login(users["norole"])
    assert c.get("/").status_code == 403


def _alert(make_source, seeded_rules, path="/x"):
    src = make_source("auth", "auth_json")
    recs = [auth_rec(T0, ip="203.0.113.77", user=f"u{i}") for i in range(12)]
    write_ndjson(Path(src.root_path) / "a.ndjson", recs + [auth_rec(T0.replace(hour=12), outcome="success")])
    import_source_file(src, "a.ndjson")
    run_detection("live", "AUTH")
    return Alert.objects.get(domain="AUTH")


def test_role_enforcement_on_mutations(users, make_source, seeded_rules):
    a = _alert(make_source, seeded_rules)
    viewer, analyst, admin = login(users["viewer"]), login(users["analyst"]), login(users["admin"])
    data = {"to_status": "ACKNOWLEDGED", "to_assessment": "NEEDS_REVIEW", "note": "looking"}
    assert viewer.post(f"/alerts/{a.pk}/triage/", data).status_code == 403
    assert analyst.post(f"/alerts/{a.pk}/triage/", data).status_code == 302
    a.refresh_from_db()
    assert a.workflow_status == "ACKNOWLEDGED"
    assert (
        analyst.post("/models/whatever/action/", {"action": "activate", "reason": "xxxxxx"}).status_code
        == 403
    )
    assert analyst.post("/sources/", {"name": "x"}).status_code == 403
    assert analyst.get("/settings/rules/AUTH-001/").status_code == 403
    assert admin.get("/settings/rules/AUTH-001/").status_code == 200
    assert (
        viewer.post(
            "/datasets/", {"action": "synthetic", "dataset_id": "x1", "seed": 1, "captures": 4}
        ).status_code
        == 403
    )
    assert not Job.objects.exists()


def test_get_never_mutates(users, make_source, seeded_rules):
    a = _alert(make_source, seeded_rules)
    c = login(users["admin"])
    c.get(f"/alerts/{a.pk}/triage/?to_status=CLOSED&to_assessment=FALSE_POSITIVE&note=xxxxxx")
    c.get("/models/x/action/?action=activate")
    a.refresh_from_db()
    assert a.workflow_status == "NEW"


def test_csrf_and_cross_site_protection(users, make_source, seeded_rules):
    a = _alert(make_source, seeded_rules)
    c = Client(enforce_csrf_checks=True)
    c.login(username="analyst1", password=PW)
    data = {"to_status": "ACKNOWLEDGED", "to_assessment": "NEEDS_REVIEW", "note": "x"}
    assert c.post(f"/alerts/{a.pk}/triage/", data).status_code == 403  # no CSRF token
    assert c.get("/alerts/", HTTP_SEC_FETCH_SITE="cross-site").status_code == 403
    assert c.post(f"/alerts/{a.pk}/triage/", data, HTTP_ORIGIN="http://evil.example").status_code == 403
    assert c.post(f"/alerts/{a.pk}/triage/", data, HTTP_ORIGIN="null").status_code == 403
    assert Client().get("/login/", HTTP_HOST="attacker.example").status_code == 400  # DNS rebinding Host


def test_log_content_is_escaped(users, make_source, seeded_rules):
    src = make_source("web")
    evil_sensor = "<script>alert(1)</script>"
    recs = [
        http_rec(
            T0, ip="203.0.113.99", path=f"/p{i}/<img src=x onerror=alert(1)>", status=404, sensor=evil_sensor
        )
        for i in range(40)
    ]
    write_ndjson(Path(src.root_path) / "x.ndjson", recs + [http_rec(T0.replace(hour=12))])
    import_source_file(src, "x.ndjson")
    run_detection("live", "HTTP")
    a = Alert.objects.get(domain="HTTP")
    html = login(users["viewer"]).get(f"/alerts/{a.pk}/").content.decode()
    assert "<script>alert(1)</script>" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html or "{other}" in html


def test_raw_identity_hidden_without_policy(users, make_source, seeded_rules):
    a = _alert(make_source, seeded_rules)
    html = login(users["admin"]).get(f"/alerts/{a.pk}/?raw=1").content.decode()
    assert "203.0.113.77" not in html


def test_job_cancel_permissions(users):
    from ai_threat_detection.worker.runner import enqueue

    j = enqueue("detect", {"namespace": "live"}, users["admin"])
    analyst = Client()
    analyst.login(username="analyst1", password=PW)
    analyst.post(f"/jobs/{j.pk}/cancel/")
    j.refresh_from_db()
    assert j.status == "QUEUED"  # analyst may not cancel someone else's job
    login(users["admin"]).post(f"/jobs/{j.pk}/cancel/")
    j.refresh_from_db()
    assert j.status == "CANCELLED"


def test_report_access_and_path_safety(users, make_source, seeded_rules):
    from ai_threat_detection.reports.export import export_report

    _alert(make_source, seeded_rules)
    priv = export_report({"namespace": "live", "days": 30}, actor=users["analyst"])
    pub = export_report({"namespace": "live", "days": 30, "public_draft": True}, actor=users["analyst"])
    viewer = login(users["viewer"])
    assert viewer.get(f"/reports/{priv['report_id']}/md/").status_code == 403
    r = viewer.get(f"/reports/{pub['report_id']}/md/")
    body = b"".join(r.streaming_content).decode()
    assert r.status_code == 200 and "DRAFT" in body and "ip_" not in body
    assert login(users["analyst"]).get(f"/reports/{priv['report_id']}/exe/").status_code == 404
    hr = login(users["analyst"]).get(f"/reports/{priv['report_id']}/html/")
    assert "default-src 'none'" in hr["Content-Security-Policy"]


def test_source_registration_rejects_paths_outside_roots(users, tmp_path):
    c = login(users["admin"])
    r = c.post(
        "/sources/",
        {
            "name": "bad",
            "source_type": "http_json",
            "root_path": str(tmp_path),
            "file_pattern": "*.ndjson",
            "provenance": "USER_IMPORTED",
            "privacy_class": "PRIVATE",
            "sensor_name": "s",
            "stale_after_seconds": 900,
            "reason": "testing",
        },
    )
    assert r.status_code == 200 and "ATD_ALLOWED_SOURCE_ROOTS" in r.content.decode()
    r = c.post(
        "/sources/",
        {
            "name": "bad2",
            "source_type": "http_json",
            "root_path": str(tmp_path),
            "file_pattern": "../*",
            "provenance": "USER_IMPORTED",
            "privacy_class": "PRIVATE",
            "sensor_name": "s",
            "stale_after_seconds": 900,
            "reason": "testing",
        },
    )
    from ai_threat_detection.sources.models import Source

    assert not Source.objects.exists()


def test_jobs_status_json_is_read_only(users):
    from ai_threat_detection.worker.runner import enqueue

    j = enqueue("detect", {}, users["admin"])
    r = login(users["viewer"]).get(f"/jobs/status.json?ids={j.pk},abc")
    assert r.json()["jobs"][str(j.pk)]["status"] == "QUEUED"
