"""Follow a registered file (tail -F semantics) and timestamp-ordered replay.

Follow:
* Only complete lines are consumed; a partial last line waits for its newline.
* Rotation (first-line fingerprint changed): the old file is looked up among
  siblings (e.g. ``app.ndjson.1``) by fingerprint and drained from the saved
  offset before the new file starts at 0. If it cannot be found, a
  ``rotation_old_file_not_found`` note records possible data loss.
* Truncation (size < offset, same fingerprint): offset resets to 0 and a note is kept.
* Missing file / permission denied are reported in SourceHealth, not as "no threats".

Replay:
* Reads the file in order into a separate namespace (``replay:<id>``) and advances
  a logical event clock. Detection is invoked after every small chunk with
  watermark = logical clock, so windows only see events that already "arrived".
* ``speed`` > 0 sleeps (event gap / speed, capped) between records; 0 = as fast as possible.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timedelta

from django.utils import timezone

from .ingest import IngestOptions, Ingestor
from .models import IngestRun, Source, SourceCheckpoint, SourceHealth
from .paths import resolve_source_file
from .reader import head_key, identify


def _health(source: Source, **kw) -> None:
    SourceHealth.objects.update_or_create(source=source, defaults={"last_poll_at": timezone.now(), **kw})


def follow_once(source: Source, file_rel: str, namespace: str = "live", ctx=None, job_id=None) -> dict:
    """One poll step. Returns a small status dict."""
    path = resolve_source_file(source.root_path, file_rel, source.file_pattern)
    try:
        ident = identify(path, require_newline=True)
    except FileNotFoundError:
        _health(source, status="MISSING", detail="followed file not found")
        return {"status": "MISSING"}
    except PermissionError:
        _health(source, status="PERMISSION_DENIED", detail="permission denied")
        return {"status": "PERMISSION_DENIED"}
    if ident is None:
        _health(source, status="OK", detail="waiting for first complete line")
        return {"status": "WAITING"}
    notes: list[str] = []
    current = (
        SourceCheckpoint.objects.filter(
            source=source, namespace=namespace, file_rel=file_rel, is_current=True
        )
        .order_by("-updated_at")
        .first()
    )
    opts = dict(namespace=namespace, mode="FOLLOW", final=False)
    if current is not None and current.file_key != ident.file_key:
        # Rotation: drain the old file if we can find it next to the current one.
        old_rel = None
        for sib in sorted(path.parent.glob(path.name + ".*")):
            try:
                if sib.is_file() and head_key(sib) == current.file_key:
                    old_rel = sib.relative_to(path.parent).as_posix()
                    break
            except OSError:
                continue
        if old_rel is not None:
            rel_parent = file_rel.rsplit("/", 1)[0] + "/" if "/" in file_rel else ""
            Ingestor(
                source, IngestOptions(namespace=namespace, mode="FOLLOW", final=True), ctx, job_id
            ).import_file(rel_parent + old_rel)
            notes.append("rotated_old_file_drained")
        else:
            notes.append("rotation_old_file_not_found_possible_data_loss")
        current.is_current = False
        current.save(update_fields=["is_current"])
    run: IngestRun = Ingestor(source, IngestOptions(**opts), ctx, job_id).import_file(file_rel)
    SourceCheckpoint.objects.filter(source=source, namespace=namespace, file_key=ident.file_key).update(
        is_current=True, file_rel=file_rel
    )
    if notes:
        run.notes.extend(notes)
        run.save(update_fields=["notes"])
    health = SourceHealth.objects.filter(source=source).first()
    if health and health.last_data_at and source.stale_after_seconds:
        if timezone.now() - health.last_data_at > timedelta(seconds=source.stale_after_seconds):
            _health(source, status="STALE", detail="no new data within stale_after_seconds")
    return {"status": "OK", "accepted": run.accepted, "rejected": run.rejected, "notes": run.notes}


def follow(
    source: Source,
    file_rel: str,
    namespace: str = "live",
    duration_s: float = 60.0,
    poll_s: float = 1.0,
    ctx=None,
    job_id=None,
    after_poll: Callable[[], None] | None = None,
) -> dict:
    from ai_threat_detection.worker.context import NullContext

    ctx = ctx or NullContext()
    end = time.monotonic() + duration_s
    totals = {"polls": 0, "accepted": 0, "rejected": 0, "statuses": {}}
    while time.monotonic() < end:
        res = follow_once(source, file_rel, namespace, ctx, job_id)
        totals["polls"] += 1
        totals["accepted"] += res.get("accepted", 0)
        totals["rejected"] += res.get("rejected", 0)
        totals["statuses"][res["status"]] = totals["statuses"].get(res["status"], 0) + 1
        if after_poll is not None:
            after_poll()
        ctx.heartbeat(**{k: v for k, v in totals.items() if k != "statuses"})
        ctx.sleep(min(poll_s, max(0.0, end - time.monotonic())))
    return totals


def replay(
    source: Source,
    file_rel: str,
    namespace: str,
    speed: float = 0.0,
    on_watermark: Callable[[datetime], None] | None = None,
    chunk_size: int = 200,
    ctx=None,
    job_id=None,
    max_sleep_s: float = 2.0,
) -> IngestRun:
    if not namespace.startswith("replay:"):
        raise ValueError("replay namespace must start with 'replay:' (kept apart from live counts)")
    state: dict[str, datetime | None] = {"clock": None, "prev": None}

    def pace(t: datetime) -> None:
        prev = state["prev"]
        if speed > 0 and prev is not None and t > prev:
            time.sleep(min((t - prev).total_seconds() / speed, max_sleep_s))
        if prev is None or t > prev:
            state["prev"] = t

    def flushed(max_time: datetime | None) -> None:
        if max_time is not None and (state["clock"] is None or max_time > state["clock"]):
            state["clock"] = max_time
        if on_watermark is not None and state["clock"] is not None:
            on_watermark(state["clock"])

    opts = IngestOptions(
        namespace=namespace,
        mode="REPLAY",
        final=True,
        chunk_size=chunk_size,
        on_flush=flushed,
        pace=pace if speed > 0 else None,
    )
    return Ingestor(source, opts, ctx, job_id).import_file(file_rel)
