"""Import / follow / replay pipeline: file -> bounded lines -> adapter -> redacted Event rows.

Semantics (documented in docs/SOURCES_AND_SCHEMAS.md):
* Each chunk of events, rejected records and the checkpoint advance are written in
  one transaction. A crash re-reads at most one chunk; re-inserted rows are
  de-duplicated by the deterministic ``event_id`` (at-least-once read,
  idempotent write). This is not end-to-end exactly-once for downstream jobs.
* ``event_id`` = sha256(namespace, source, file head key, byte offset), or the
  source's stable record id when configured. Identical lines at different offsets
  are different events (e.g. repeated failed logins).
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from ai_threat_detection.conf import get_config
from ai_threat_detection.normalization.privacy import content_hash, sanitized_preview
from ai_threat_detection.normalization.pseudonym import Pseudonymizer
from ai_threat_detection.worker.context import NullContext

from .adapters.base import ParseContext
from .adapters.registry import get_adapter
from .models import Event, IngestRun, RawIdentity, RejectedRecord, Source, SourceCheckpoint, SourceHealth
from .paths import resolve_source_file
from .reader import identify, iter_json_array, iter_lines, looks_like_json_array

log = logging.getLogger(__name__)

MAX_FUTURE_SKEW = timedelta(minutes=5)


def make_event_id(namespace: str, source_id: int, file_key: str, offset: int, stable_id: str | None) -> str:
    if stable_id:
        basis = f"stable\x1f{namespace}\x1f{source_id}\x1f{stable_id}"
    else:
        basis = f"loc\x1f{namespace}\x1f{source_id}\x1f{file_key}\x1f{offset}"
    return hashlib.sha256(basis.encode()).hexdigest()


def closed_until(namespace: str, domain: str) -> datetime | None:
    """Latest event-time up to which windows were already closed for this namespace/domain."""
    from ai_threat_detection.features.models import DetectionCheckpoint

    return DetectionCheckpoint.objects.filter(namespace=namespace, domain=domain).aggregate(
        m=Max("processed_until")
    )["m"]


@dataclass
class IngestOptions:
    namespace: str = "live"
    mode: str = "IMPORT"
    capture_id: str | None = None
    provenance: str | None = None
    privacy_class: str | None = None
    chunk_size: int | None = None
    final: bool = True
    from_start: bool = False
    on_flush: Callable[[datetime | None], None] | None = None
    pace: Callable[[datetime], None] | None = None
    now: Callable[[], datetime] = field(default=timezone.now)


class Ingestor:
    def __init__(self, source: Source, options: IngestOptions, ctx=None, job_id: int | None = None):
        self.source = source
        self.opt = options
        self.ctx = ctx or NullContext()
        self.cfg = get_config()
        self.adapter = get_adapter(source.source_type)
        self.pctx = ParseContext(
            pseudonymizer=Pseudonymizer.from_local_key(scope=source.pseudonym_scope),
            assume_timezone=source.assume_timezone or None,
            sensor_default=source.sensor_name,
            stable_id_field=source.stable_id_field or None,
            capture_raw_identity=source.store_raw_identity,
        )
        self.job_id = job_id
        self.chunk = options.chunk_size or self.cfg.import_chunk
        self._closed_cache: dict[str, datetime | None] = {}

    # ---- public entry points -------------------------------------------------
    def import_file(self, file_rel: str) -> IngestRun:
        path = resolve_source_file(self.source.root_path, file_rel, self.source.file_pattern)
        run = IngestRun.objects.create(
            source=self.source,
            job_id=self.job_id,
            mode=self.opt.mode,
            namespace=self.opt.namespace,
            file_rel=file_rel,
        )
        try:
            size = path.stat().st_size
            if size > self.cfg.max_file_bytes:
                return self._finish(run, "REJECTED", note="file_exceeds_ATD_MAX_FILE_BYTES")
            if self.adapter.line_format == "json" and looks_like_json_array(path):
                self._import_array(run, path, file_rel)
            else:
                self._import_lines(run, path, file_rel, final=self.opt.final)
        except PermissionError:
            self._health("PERMISSION_DENIED", "permission denied reading source file")
            return self._finish(run, "FAILED", note="permission_denied")
        except FileNotFoundError:
            self._health("MISSING", "source file not found")
            return self._finish(run, "FAILED", note="file_missing")
        except Exception:
            self._finish(run, "FAILED", note="exception")
            raise
        status = "PARTIAL" if "event_limit_reached" in run.notes else "SUCCEEDED"
        return self._finish(run, status)

    # ---- internals -------------------------------------------------------------
    def _checkpoint(self, file_key: str, file_rel: str, stat_id: str) -> SourceCheckpoint:
        cp, _ = SourceCheckpoint.objects.get_or_create(
            source=self.source,
            namespace=self.opt.namespace,
            file_key=file_key,
            defaults={"file_rel": file_rel, "stat_id": stat_id},
        )
        if self.opt.from_start:
            cp.offset = 0
            cp.line_no = 0
        return cp

    def _import_lines(self, run: IngestRun, path: Path, file_rel: str, final: bool) -> None:
        ident = identify(path, require_newline=not final)
        if ident is None:
            run.notes.append("empty_or_incomplete_first_line")
            return
        run.file_key = ident.file_key
        cp = self._checkpoint(ident.file_key, file_rel, ident.stat_id)
        if ident.size < cp.offset:
            run.notes.append("truncated_since_checkpoint_reset_to_0")
            cp.offset, cp.line_no = 0, 0
        state = _ChunkState()
        with open(path, "rb") as fh:
            for rec in iter_lines(fh, cp.offset, cp.line_no, self.cfg.max_line_bytes, final=final):
                run.records_seen += 1
                if rec.status == "oversized":
                    state.reject(rec.offset, rec.line_no, "oversized_line", b"")
                    state.advance(rec.end_offset, rec.line_no)
                else:
                    accepted_partial = self._handle_record(
                        state, ident.file_key, rec.offset, rec.line_no, rec.data, rec.status == "partial", run
                    )
                    if rec.status == "partial" and not accepted_partial:
                        run.partial_pending += 1
                        break  # do not advance past an incomplete trailing line
                    state.advance(rec.end_offset, rec.line_no)
                if state.size() >= self.chunk:
                    self._flush(run, cp, state, ident.size)
                if run.accepted >= self.cfg.max_events_per_job:
                    run.notes.append("event_limit_reached")
                    break
        self._flush(run, cp, state, ident.size, final=True)

    def _import_array(self, run: IngestRun, path: Path, file_rel: str) -> None:
        ident = identify(path)
        if ident is None:
            run.notes.append("empty_file")
            return
        run.file_key = ident.file_key
        cp = self._checkpoint(ident.file_key, file_rel, ident.stat_id)
        state = _ChunkState()
        try:
            items = iter_json_array(path, self.cfg.max_json_array_bytes)
            for idx, obj, reason in items:
                if idx < cp.offset:
                    continue
                run.records_seen += 1
                if reason:
                    state.reject(idx, idx + 1, reason, b"")
                else:
                    self._handle_parsed(state, ident.file_key, idx, idx + 1, obj, b"", run)
                state.advance(idx + 1, idx + 1)
                if state.size() >= self.chunk:
                    self._flush(run, cp, state, ident.size)
        except ValueError as exc:
            state.reject(0, 0, str(exc)[:64], b"")
        self._flush(run, cp, state, ident.size, final=True)

    def _handle_record(self, state, file_key, offset, line_no, data, is_partial, run) -> bool:
        obj, reason = self.adapter.decode_line(data, offset == 0)
        if obj is None and reason is None:
            run.blank_lines += 1
            return True
        if reason:
            if is_partial:
                return False
            state.reject(offset, line_no, reason, data)
            return True
        return self._handle_parsed(state, file_key, offset, line_no, obj, data, run, is_partial)

    def _handle_parsed(self, state, file_key, offset, line_no, obj, data, run, is_partial=False) -> bool:
        outcome = self.adapter.parse(obj, self.pctx)
        if outcome.skip_reason:
            state.skip(outcome.skip_reason)
            return True
        if outcome.event is None:
            state.reject(offset, line_no, outcome.reject_reason or "rejected", data)
            return True
        pe = outcome.event
        flags = list(pe.quality_flags)
        if is_partial:
            flags.append("no_trailing_newline")
        excluded = False
        now = self.opt.now()
        if pe.event_time > now + MAX_FUTURE_SKEW:
            flags.append("future_timestamp")
            excluded = True
            run.future_events += 1
        closed = self._closed(pe.domain)
        if not excluded and closed is not None and pe.event_time < closed:
            flags.append("late_after_window_close")
            excluded = True
            run.late_events += 1
        if pe.entity_key is None:
            excluded = True
        ev = Event(
            event_id=make_event_id(self.opt.namespace, self.source.id, file_key, offset, pe.stable_id),
            namespace=self.opt.namespace,
            source=self.source,
            source_type=self.source.source_type,
            schema_version=pe.schema_version,
            domain=pe.domain,
            event_time=pe.event_time,
            ingested_at=now,
            file_key=file_key,
            offset=offset,
            line_no=line_no,
            provenance=self.opt.provenance or self.source.provenance,
            privacy_class=self.opt.privacy_class or self.source.privacy_class,
            entity_key=pe.entity_key,
            user_key=pe.user_key,
            host_key=pe.host_key,
            fields=pe.fields,
            quality_flags=flags,
            capture_id=self.opt.capture_id,
            ingest_run=run,
            excluded_from_windows=excluded,
        )
        state.events.append(ev)
        state.raw_ids.update(pe.raw_identities)
        for f in flags:
            state.flag_counts[f] += 1
        if self.opt.pace is not None:
            self.opt.pace(pe.event_time)
        return True

    def _closed(self, domain: str) -> datetime | None:
        if domain not in self._closed_cache:
            self._closed_cache[domain] = closed_until(self.opt.namespace, domain)
        return self._closed_cache[domain]

    def _flush(
        self, run: IngestRun, cp: SourceCheckpoint, state: _ChunkState, size: int, final: bool = False
    ) -> None:
        self.ctx.check()
        if not state.dirty and not final:
            return
        with transaction.atomic():
            ids = [e.event_id for e in state.events]
            existing = (
                set(Event.objects.filter(event_id__in=ids).values_list("event_id", flat=True))
                if ids
                else set()
            )
            new = [e for e in state.events if e.event_id not in existing]
            # Same id twice within one chunk (stable ids) counts once.
            seen: set[str] = set()
            unique_new = []
            for e in new:
                if e.event_id in seen:
                    existing.add(e.event_id)
                    continue
                seen.add(e.event_id)
                unique_new.append(e)
            Event.objects.bulk_create(unique_new, ignore_conflicts=True, batch_size=500)
            dup = len(state.events) - len(unique_new)
            if state.rejects:
                rej_objs = []
                for off, ln, reason, data in state.rejects:
                    rej_objs.append(
                        RejectedRecord(
                            source=self.source,
                            namespace=self.opt.namespace,
                            ingest_run=run,
                            file_key=run.file_key or "",
                            offset=off,
                            line_no=ln,
                            reason=reason,
                            content_sha256=content_hash(data) if data else "",
                            preview=sanitized_preview(data)
                            if (data and self.source.store_invalid_preview)
                            else "",
                        )
                    )
                RejectedRecord.objects.bulk_create(rej_objs, ignore_conflicts=True, batch_size=500)
            if state.raw_ids and self.source.store_raw_identity:
                RawIdentity.objects.bulk_create(
                    [
                        RawIdentity(pseudonym=p, kind=k, raw_value=v, source=self.source)
                        for p, (k, v) in state.raw_ids.items()
                    ],
                    ignore_conflicts=True,
                )
            cp.offset = state.offset if state.offset is not None else cp.offset
            cp.line_no = state.line_no if state.line_no is not None else cp.line_no
            cp.size_seen = size
            cp.completed = final and self.opt.final
            cp.save()
            run.accepted += len(unique_new)
            run.duplicates += dup
            run.rejected += len(state.rejects)
            for r in state.rejects:
                run.reject_reasons[r[2]] = run.reject_reasons.get(r[2], 0) + 1
            for k, v in state.flag_counts.items():
                run.quality_flag_counts[k] = run.quality_flag_counts.get(k, 0) + v
            for k, v in state.skips.items():
                run.skipped += v
                run.skip_reasons[k] = run.skip_reasons.get(k, 0) + v
            times = sorted(e.event_time for e in unique_new)
            if times:
                if run.first_event_time is None or times[0] < run.first_event_time:
                    run.first_event_time = times[0]
                if run.last_event_time is None or times[-1] > run.last_event_time:
                    run.last_event_time = times[-1]
                prev = state.prev_time
                gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
                if prev is not None and times[0] > prev:
                    gaps.append((times[0] - prev).total_seconds())
                if gaps:
                    g = max(gaps)
                    run.max_event_gap_seconds = max(run.max_event_gap_seconds or 0.0, g)
                state.prev_time = times[-1] if prev is None else max(prev, times[-1])
            run.save()
        max_time = max((e.event_time for e in unique_new), default=None)
        self.ctx.heartbeat(accepted=run.accepted, rejected=run.rejected, duplicates=run.duplicates)
        state.reset()
        if self.opt.on_flush is not None:
            self.opt.on_flush(max_time)
            self._closed_cache.clear()  # detection may have closed more windows

    def _health(self, status: str, detail: str) -> None:
        SourceHealth.objects.update_or_create(
            source=self.source, defaults={"status": status, "detail": detail, "last_poll_at": timezone.now()}
        )

    def _finish(self, run: IngestRun, status: str, note: str | None = None) -> IngestRun:
        if note:
            run.notes.append(note)
        run.status = status
        run.finished_at = timezone.now()
        run.save()
        if status in {"SUCCEEDED", "PARTIAL"}:
            defaults = {"status": "OK", "detail": "", "last_poll_at": timezone.now()}
            if run.accepted:
                defaults["last_data_at"] = timezone.now()
                defaults["last_event_time"] = run.last_event_time
            SourceHealth.objects.update_or_create(source=self.source, defaults=defaults)
        return run


class _ChunkState:
    def __init__(self) -> None:
        self.events: list[Event] = []
        self.rejects: list[tuple[int, int, str, bytes]] = []
        self.raw_ids: dict[str, tuple[str, str]] = {}
        self.flag_counts: Counter[str] = Counter()
        self.skips: Counter[str] = Counter()
        self.offset: int | None = None
        self.line_no: int | None = None
        self.prev_time: datetime | None = None
        self.dirty = False

    def reject(self, offset: int, line_no: int, reason: str, data: bytes) -> None:
        self.rejects.append((offset, line_no, reason, data))
        self.dirty = True

    def skip(self, reason: str) -> None:
        self.skips[reason] += 1
        self.dirty = True

    def advance(self, offset: int, line_no: int) -> None:
        self.offset = offset
        self.line_no = line_no
        self.dirty = True

    def size(self) -> int:
        return len(self.events) + len(self.rejects)

    def reset(self) -> None:
        self.events = []
        self.rejects = []
        self.raw_ids = {}
        self.flag_counts = Counter()
        self.skips = Counter()
        self.dirty = False


def import_source_file(
    source: Source, file_rel: str, options: IngestOptions | None = None, ctx=None, job_id=None
) -> IngestRun:
    return Ingestor(source, options or IngestOptions(), ctx=ctx, job_id=job_id).import_file(file_rel)
