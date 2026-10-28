import subprocess
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from django.utils import timezone

from ai_threat_detection.publishing.publish_check import publish_check, scan_text
from ai_threat_detection.worker import handlers
from ai_threat_detection.worker.models import Job
from ai_threat_detection.worker.runner import (
    claim,
    enqueue,
    execute,
    recover_stale,
    request_cancel,
    run_inline,
    run_worker,
)


@pytest.mark.django_db
def test_lock_prevents_two_training_jobs():
    a = enqueue("train", {"experiment": "x", "domain": "AUTH"}, "t")
    b = enqueue("evaluate", {"experiment": "x", "domain": "AUTH", "model_id": "m"}, "t")
    assert claim(a, "w1")
    assert not claim(b, "w2")  # same "training" lock
    c = enqueue("import", {"source": "s1", "file": "f"}, "t")
    assert claim(c, "w2")  # different lock


@pytest.mark.django_db
def test_cancel_and_timeout(monkeypatch):
    def slow(params, ctx, job):
        for _ in range(200):
            ctx.heartbeat(step=1)
            time.sleep(0.02)
        return {}

    monkeypatch.setitem(handlers.HANDLERS, "detect", slow)
    j = enqueue("detect", {}, "t", timeout_seconds=10)
    claim(j, "w")
    Job.objects.filter(pk=j.pk).update(status="CANCEL_REQUESTED")
    j.refresh_from_db()
    assert execute(j).status == "CANCELLED"
    j2 = enqueue("detect", {"namespace": "x"}, "t", timeout_seconds=10)
    j2.timeout_seconds = 0
    Job.objects.filter(pk=j2.pk).update(timeout_seconds=0)
    claim(j2, "w")
    j2.refresh_from_db()
    assert execute(j2).status == "TIMED_OUT"


@pytest.mark.django_db
def test_stale_recovery_requeues_idempotent_and_fails_others():
    old = timezone.now() - timedelta(hours=1)
    a = enqueue("import", {"source": "s", "file": "f"}, "t")
    b = enqueue("train", {"experiment": "e", "domain": "AUTH"}, "t")
    for j in (a, b):
        claim(j, "dead-worker")
    Job.objects.update(heartbeat_at=old)
    assert recover_stale() == 2
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.status == "QUEUED" and b.status == "FAILED" and "stale" in b.error


@pytest.mark.django_db
def test_failed_job_error_is_sanitized(monkeypatch):
    def boom(params, ctx, job):
        raise RuntimeError("connect failed password=hunter2 token=abc123")

    monkeypatch.setitem(handlers.HANDLERS, "detect", boom)
    j = run_inline("detect", {}, "t")
    assert j.status == "FAILED" and "hunter2" not in j.error and "abc123" not in j.error


@pytest.mark.django_db
def test_cancel_queued_and_worker_once(monkeypatch):
    done = []
    monkeypatch.setitem(handlers.HANDLERS, "detect", lambda p, c, j: done.append(j.pk) or {})
    j = enqueue("detect", {"namespace": "a"}, "t")
    request_cancel(j, "t")
    j.refresh_from_db()
    assert j.status == "CANCELLED"
    k = enqueue("detect", {"namespace": "b"}, "t")
    assert run_worker(once=True) == 1 and done == [k.pk]


@pytest.mark.django_db(transaction=True)
def test_sqlite_wal_concurrent_reader_during_writes(make_source):
    """UI reads must not block while the worker writes (WAL + busy timeout)."""
    from django.db import connection, connections

    from ai_threat_detection.sources.models import Event

    from .conftest import T0, http_rec, write_ndjson

    with connection.cursor() as c:
        c.execute("PRAGMA journal_mode")
        assert c.fetchone()[0] == "wal"
    src = make_source()
    write_ndjson(
        Path(src.root_path) / "big.ndjson", [http_rec(T0 + timedelta(milliseconds=i)) for i in range(4000)]
    )
    errors, reads = [], []

    def reader():
        try:
            for _ in range(20):
                reads.append(Event.objects.count())
                time.sleep(0.01)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            connections.close_all()

    from ai_threat_detection.sources.ingest import IngestOptions, import_source_file

    t = threading.Thread(target=reader)
    t.start()
    import_source_file(src, "big.ndjson", IngestOptions(chunk_size=200))
    t.join()
    assert not errors and len(reads) == 20 and Event.objects.count() == 4000


def test_scan_text_finds_leaks():
    ctx = {"machine_identifiers": {"someuserxyz"}, "identity_allowlist": set()}
    text = "\n".join(
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            r"path C:\Users\someone\secret.txt",
            "contact real.person@company-domain.com",
            "ip 10.1.2.3 and 8.8.8.8 and doc 203.0.113.5",
            "built by someuserxyz",
            "api_key = 'abcdefghijklmnop1234'",
        ]
    )
    kinds = {f.kind for f in scan_text("x.md", text, ctx)}
    assert {
        "secret:private_key",
        "home_path",
        "email",
        "ip_address",
        "machine_identifier",
        "secret:assigned_secret",
    } <= kinds
    ok = scan_text("y.md", "see user@example.com and 192.0.2.1 and C:\\Users\\<user>\\x", ctx)
    assert ok == []


def test_publish_check_on_temp_repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / ".gitignore").write_text(".local/\n.venv/\n*.sqlite3\n.env\n*.skops\n", encoding="utf-8")
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    res = publish_check(repo)
    assert res["result"] == "PASS_WITHIN_SCOPE" and res["gitleaks"]["status"] in {"NOT_RUN", "RAN"}
    (repo / "dump.sqlite3.bak").write_text("", encoding="utf-8")
    (repo / "events.ndjson").write_text("{}\n", encoding="utf-8")
    (repo / "manifest.json").write_text('{"privacy_class": "PRIVATE"}', encoding="utf-8")
    res = publish_check(repo)
    kinds = {f["kind"] for f in res["findings"]}
    assert res["result"] == "FAIL" and {"forbidden_file_type", "privacy_class"} <= kinds
    assert res["staged_files"] == []  # read-only: nothing staged
