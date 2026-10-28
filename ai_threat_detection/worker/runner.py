"""Local job queue on SQLite (no Redis/Celery).

* Claim = conditional UPDATE inside an IMMEDIATE transaction, after checking that
  no live job holds the same ``lock_key`` (one training job at a time; one
  ingest job per source).
* Jobs cooperate: ``ctx.check()`` raises on cancel request or timeout; ``ctx.heartbeat()``
  records progress. A RUNNING job whose heartbeat is older than ATD_JOB_STALE_SECONDS
  is recovered: re-queued if attempts remain (idempotent kinds), else FAILED.
"""

from __future__ import annotations

import logging
import os
import socket
import time
import traceback
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from ai_threat_detection.conf import get_config
from ai_threat_detection.normalization.privacy import scrub_text

from .context import JobCancelledError, JobTimeoutError
from .models import Job

log = logging.getLogger(__name__)

IDEMPOTENT_KINDS = {"import", "detect", "import_dataset"}
LOCKS = {
    "train": lambda p: "training",
    "evaluate": lambda p: "training",
    "create_experiment": lambda p: "training",
    "import": lambda p: f"source:{p.get('source')}",
    "follow": lambda p: f"source:{p.get('source')}",
    "replay": lambda p: f"source:{p.get('source')}",
    "detect": lambda p: (
        f"detect:ds:{p['dataset']}" if p.get("dataset") else f"detect:{p.get('namespace', 'live')}"
    ),
    "import_dataset": lambda p: f"dataset:{p.get('dataset')}",
    "lab_capture": lambda p: "lab",
    "generate_synthetic": lambda p: f"dataset:{p.get('dataset_id')}",
    "report": lambda p: "",
}
MAX_QUEUED_PER_USER = 20


class DbJobContext:
    def __init__(self, job: Job):
        self.job = job
        self.job_id = job.pk
        self._start = time.monotonic()
        self._last_check = 0.0
        self._last_beat = 0.0
        self.progress: dict[str, Any] = {}

    def check(self) -> None:
        if time.monotonic() - self._start > self.job.timeout_seconds:
            raise JobTimeoutError("timeout")
        now = time.monotonic()
        if now - self._last_check < 1.0:
            return
        self._last_check = now
        status = Job.objects.filter(pk=self.job.pk).values_list("status", flat=True).first()
        if status == "CANCEL_REQUESTED":
            raise JobCancelledError("cancel requested")

    def heartbeat(self, **progress: Any) -> None:
        self.progress.update(
            {k: v for k, v in progress.items() if isinstance(v, int | float | str | bool | None)}
        )
        now = time.monotonic()
        if now - self._last_beat >= 2.0:
            self._last_beat = now
            Job.objects.filter(pk=self.job.pk).update(heartbeat_at=timezone.now(), progress=self.progress)
        self.check()

    def sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.heartbeat()
            time.sleep(min(0.5, max(0.0, end - time.monotonic())))


def enqueue(kind: str, params: dict[str, Any], actor=None, timeout_seconds: int = 3600) -> Job:
    if kind not in LOCKS:
        raise ValueError(f"unknown job kind {kind}")
    user = actor if getattr(actor, "is_authenticated", False) else None
    if user is not None:
        active = Job.objects.filter(created_by=user, status__in=["QUEUED", "RUNNING"]).count()
        if active >= MAX_QUEUED_PER_USER:
            raise ValueError("too many active jobs for this user")
    return Job.objects.create(
        kind=kind,
        params=params,
        lock_key=LOCKS[kind](params),
        created_by=user,
        created_by_label=user.get_username() if user else str(actor or "cli"),
        timeout_seconds=max(10, min(timeout_seconds, 24 * 3600)),
        max_attempts=3 if kind in IDEMPOTENT_KINDS else 1,
    )


def worker_identity() -> str:
    return f"{socket.gethostname()[:40]}:{os.getpid()}"


def recover_stale() -> int:
    stale_before = timezone.now() - timedelta(seconds=get_config().job_stale_seconds)
    n = 0
    for job in Job.objects.filter(status__in=["RUNNING", "CANCEL_REQUESTED"], heartbeat_at__lt=stale_before):
        if job.status == "CANCEL_REQUESTED":
            Job.objects.filter(pk=job.pk).update(
                status="CANCELLED", finished_at=timezone.now(), error="worker lost during cancel"
            )
        elif job.kind in IDEMPOTENT_KINDS and job.attempts < job.max_attempts:
            Job.objects.filter(pk=job.pk).update(
                status="QUEUED", worker_id="", error="re-queued after stale heartbeat"
            )
        else:
            Job.objects.filter(pk=job.pk).update(
                status="FAILED", finished_at=timezone.now(), error="worker lost (stale heartbeat)"
            )
        n += 1
    return n


def claim(job: Job, worker_id: str) -> bool:
    with transaction.atomic():
        if job.lock_key:
            busy = (
                Job.objects.filter(lock_key=job.lock_key, status__in=["RUNNING", "CANCEL_REQUESTED"])
                .exclude(pk=job.pk)
                .exists()
            )
            if busy:
                return False
        now = timezone.now()
        updated = Job.objects.filter(pk=job.pk, status="QUEUED").update(
            status="RUNNING", worker_id=worker_id, started_at=now, heartbeat_at=now, attempts=job.attempts + 1
        )
        return updated == 1


def claim_next(worker_id: str) -> Job | None:
    for job in Job.objects.filter(status="QUEUED").order_by("created_at", "id")[:50]:
        if claim(job, worker_id):
            job.refresh_from_db()
            return job
    return None


def execute(job: Job) -> Job:
    from .handlers import HANDLERS

    ctx = DbJobContext(job)
    status, error, result = "SUCCEEDED", "", {}
    try:
        result = HANDLERS[job.kind](job.params, ctx, job) or {}
    except JobCancelledError:
        status, error = "CANCELLED", "cancelled by user"
    except JobTimeoutError:
        status, error = "TIMED_OUT", f"exceeded {job.timeout_seconds}s"
    except Exception as exc:  # noqa: BLE001 - recorded, sanitized, worker keeps running
        status = "FAILED"
        error = scrub_text(f"{type(exc).__name__}: {exc}", max_len=480)[0]
        log.error("job %s (%s) failed: %s", job.pk, job.kind, error)
        log.debug(traceback.format_exc())
    Job.objects.filter(pk=job.pk).update(
        status=status,
        error=error,
        result=_jsonable(result),
        finished_at=timezone.now(),
        heartbeat_at=timezone.now(),
        progress=ctx.progress,
    )
    job.refresh_from_db()
    return job


def run_inline(kind: str, params: dict[str, Any], actor=None, timeout_seconds: int = 3600) -> Job:
    """Used by CLI commands: same queue record + locks, executed in this process."""
    job = enqueue(kind, params, actor, timeout_seconds)
    if not claim(job, worker_identity() + ":inline"):
        Job.objects.filter(pk=job.pk).update(
            status="FAILED", error=f"lock busy: {job.lock_key}", finished_at=timezone.now()
        )
        job.refresh_from_db()
        return job
    job.refresh_from_db()
    return execute(job)


def request_cancel(job: Job, actor) -> bool:
    updated = Job.objects.filter(pk=job.pk, status="RUNNING").update(status="CANCEL_REQUESTED")
    if not updated:
        updated = Job.objects.filter(pk=job.pk, status="QUEUED").update(
            status="CANCELLED", finished_at=timezone.now(), error="cancelled before start"
        )
    from ai_threat_detection.core.audit import audit

    audit(actor, "job.cancel", "job", job.pk, "")
    return bool(updated)


def run_worker(
    poll_s: float = 1.0, once: bool = False, max_runtime_s: float | None = None, stop_flag=None
) -> int:
    wid = worker_identity()
    deadline = (time.monotonic() + max_runtime_s) if max_runtime_s else None
    done = 0
    while True:
        recover_stale()
        job = claim_next(wid)
        if job is not None:
            execute(job)
            done += 1
            continue
        if once:
            return done
        if deadline and time.monotonic() > deadline:
            return done
        if stop_flag is not None and stop_flag():
            return done
        time.sleep(poll_s)


def _jsonable(obj: Any, depth: int = 0) -> Any:
    if depth > 6:
        return str(obj)[:200]
    if isinstance(obj, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_jsonable(v, depth + 1) for v in obj][:500]
    if obj is None or isinstance(obj, bool | int | float | str):
        return obj
    return str(obj)
