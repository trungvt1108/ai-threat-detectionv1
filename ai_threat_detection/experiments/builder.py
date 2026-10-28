"""Package an operator's own exported logs into a dataset (``build_dataset``).

The input files are split by event time into fixed-length captures (default one
day, aligned to UTC). The last ``gap_seconds`` of every capture are left out so
that any chronological train/validation/test boundary has a purge gap; the
number of lines dropped this way is recorded in the manifest. Lines that cannot
be parsed (or are out of scope for the adapter) are kept with the capture of
the preceding parsed line, so import statistics and health rules see them.

Labels are optional. Without a labels file the background label is ``UNKNOWN``
(training then needs ``--train-on-unknown`` and evaluation has no positives);
``background="BENIGN"`` records the operator's explicit assertion instead.

The capture files are verbatim copies of the input lines and live only under
``.local/datasets/<dataset_id>/`` (ignored by Git, privacy class ``PRIVATE`` by
default). Nothing outside the allowed source roots is read.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ai_threat_detection.conf import get_config
from ai_threat_detection.normalization.pseudonym import Pseudonymizer
from ai_threat_detection.normalization.timeparse import parse_timestamp, validate_timezone
from ai_threat_detection.sources.adapters.base import ParseContext
from ai_threat_detection.sources.adapters.registry import get_adapter
from ai_threat_detection.sources.paths import validate_source_root
from ai_threat_detection.sources.reader import iter_lines

from .datasets import DOMAIN_FILES, MANIFEST_VERSION, VALID_LABELS, DatasetError, dataset_dir

BUILDER_VERSION = "atd-dataset-builder-1.0.0"


@dataclass
class InputSpec:
    domain: str  # HTTP | AUTH
    source_type: str
    path: str


@dataclass
class _Bucket:
    index: int
    lines: dict[str, list[bytes]] = field(default_factory=dict)
    events: Counter[str] = field(default_factory=Counter)


def _check_inputs(inputs: list[InputSpec]) -> list[tuple[InputSpec, Path]]:
    cfg = get_config()
    out = []
    for spec in inputs:
        if spec.domain not in DOMAIN_FILES:
            raise DatasetError(f"unsupported domain {spec.domain}")
        adapter = get_adapter(spec.source_type)
        if spec.domain not in adapter.domains:
            raise DatasetError(f"{spec.source_type} does not produce {spec.domain} events")
        p = Path(spec.path).resolve()
        validate_source_root(str(p.parent))  # raises PathNotAllowedError outside allowed roots
        if not p.is_file():
            raise DatasetError(f"input file not found: {p.name}")
        if p.stat().st_size > cfg.max_file_bytes:
            raise DatasetError(f"input file exceeds ATD_MAX_FILE_BYTES: {p.name}")
        out.append((spec, p))
    types: dict[str, str] = {}
    for spec, _ in out:
        if types.setdefault(spec.domain, spec.source_type) != spec.source_type:
            raise DatasetError(f"all {spec.domain} inputs must use the same source type")
    if not out:
        raise DatasetError("no input files")
    return out


def _load_labels(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    p = Path(path).resolve()
    validate_source_root(str(p.parent))
    data = json.loads(p.read_text(encoding="utf-8"))
    intervals = data.get("intervals") if isinstance(data, dict) else data
    if not isinstance(intervals, list):
        raise DatasetError("labels file must be a list of intervals or {'intervals': [...]}")
    out = []
    for iv in intervals:
        if iv.get("label") not in VALID_LABELS or iv.get("domain") not in DOMAIN_FILES:
            raise DatasetError("each interval needs a valid label and domain (HTTP/AUTH)")
        ent = iv.get("entity", "*")
        if ent != "*" and not (isinstance(ent, dict) and ent.get("kind") and ent.get("value")):
            raise DatasetError('entity must be "*" or {"kind": "ip", "value": "..."}')
        s, e = parse_timestamp(iv.get("start")).value, parse_timestamp(iv.get("end")).value
        if s is None or e is None or e <= s:
            raise DatasetError("interval start/end must be ISO 8601 with offset, end > start")
        out.append({**iv, "_start": s, "_end": e})
    return out


def build_dataset(
    dataset_id: str,
    inputs: list[InputSpec],
    *,
    assume_timezone: str = "",
    capture_hours: float = 24.0,
    gap_seconds: int = 600,
    labels_path: str | None = None,
    background: str = "UNKNOWN",
    name: str = "",
    description: str = "",
    provenance: str = "USER_IMPORTED",
    privacy_class: str = "PRIVATE",
) -> dict[str, Any]:
    if not dataset_id or not all(c.isalnum() or c in "-_" for c in dataset_id) or len(dataset_id) > 60:
        raise DatasetError("dataset id: letters, digits, '-' and '_' only (max 60)")
    if background not in {"UNKNOWN", "BENIGN"}:
        raise DatasetError("background must be UNKNOWN or BENIGN")
    if assume_timezone and not validate_timezone(assume_timezone):
        raise DatasetError("unknown timezone")
    bucket_s = int(capture_hours * 3600)
    if bucket_s < 600 or gap_seconds < 0 or gap_seconds >= bucket_s // 2:
        raise DatasetError("capture length must be >= 10 min and gap < half a capture")
    root = dataset_dir(dataset_id)
    if root.exists():
        raise DatasetError("dataset directory exists; choose a new id")
    checked = _check_inputs(inputs)
    labels = _load_labels(labels_path)
    cfg = get_config()

    pctx = ParseContext(
        pseudonymizer=Pseudonymizer.from_local_key(),
        assume_timezone=assume_timezone or None,
        reference_time=datetime.now(UTC),
    )
    buckets: dict[int, _Bucket] = {}
    stats: dict[str, Any] = {"inputs": [], "dropped_in_gap": Counter(), "unplaced": Counter()}
    for spec, path in checked:
        adapter = get_adapter(spec.source_type)
        dom = spec.domain
        current: int | None = None
        pending: list[bytes] = []  # unparsed lines before the first parsed one
        counts: Counter[str] = Counter()
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for rec in iter_lines(fh, 0, 0, cfg.max_line_bytes, final=True):
                h.update(rec.data)
                if rec.status == "oversized":
                    counts["oversized"] += 1
                    continue
                line = rec.data.rstrip(b"\r")
                obj, reason = adapter.decode_line(line, rec.offset == 0)
                when = None
                if obj is not None:
                    outcome = adapter.parse(obj, pctx)
                    if outcome.event is not None:
                        when = outcome.event.event_time
                    else:
                        counts["skipped" if outcome.skip_reason else "rejected"] += 1
                elif reason is None:
                    continue  # blank
                else:
                    counts["rejected"] += 1
                if when is None:
                    if current is None:
                        pending.append(line)
                    elif current >= 0:
                        buckets[current].lines.setdefault(dom, []).append(line)
                    continue
                epoch = int(when.timestamp())
                idx, pos = divmod(epoch, bucket_s)
                if pos >= bucket_s - gap_seconds:
                    stats["dropped_in_gap"][dom] += 1
                    current = -1  # following unparsed lines are dropped with it
                    continue
                b = buckets.setdefault(idx, _Bucket(idx))
                if pending:
                    b.lines.setdefault(dom, []).extend(pending)
                    pending = []
                b.lines.setdefault(dom, []).append(line)
                b.events[dom] += 1
                counts["events"] += 1
                current = idx
        if pending:
            stats["unplaced"][dom] += len(pending)
        stats["inputs"].append(
            {"domain": dom, "type": spec.source_type, "sha256": h.hexdigest(), **dict(counts)}
        )

    nonempty = [b for b in sorted(buckets.values(), key=lambda b: b.index) if sum(b.events.values())]
    if len(nonempty) < 3:
        raise DatasetError(
            f"only {len(nonempty)} capture(s) with events; need >= 3 for train/validation/test "
            "(use more data or a smaller --capture-hours)"
        )

    sources = {
        spec.domain: {
            "type": spec.source_type,
            **({"assume_timezone": assume_timezone} if assume_timezone else {}),
        }
        for spec, _ in checked
    }
    (root / "captures").mkdir(parents=True)
    captures = []
    for b in nonempty:
        start = datetime.fromtimestamp(b.index * bucket_s, tz=UTC)
        end = start + timedelta(seconds=bucket_s - gap_seconds)
        cid = "d" + start.strftime("%Y%m%dT%H%M")
        cdir = root / "captures" / cid
        cdir.mkdir()
        files = {}
        for dom, lines in b.lines.items():
            prefix = DOMAIN_FILES[dom][0]
            ext = "log" if get_adapter(sources[dom]["type"]).line_format == "text" else "ndjson"
            fname = f"{prefix}.{ext}"
            with open(cdir / fname, "wb") as out:
                for line in lines:
                    out.write(line + b"\n")
            files[dom] = f"captures/{cid}/{fname}"
        intervals = []
        for iv in labels:
            if iv["_start"] < end and iv["_end"] > start:
                intervals.append({k: v for k, v in iv.items() if not k.startswith("_")})
        lab = {
            "capture_id": cid,
            "label_source": "operator labels file" if labels_path else "none (unlabeled operator logs)",
            "background_label": background,
            "intervals": intervals,
        }
        (cdir / "labels.json").write_text(json.dumps(lab, indent=1), encoding="utf-8")
        captures.append(
            {
                "capture_id": cid,
                "scenario_group": cid,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "files": files,
                "labels": f"captures/{cid}/labels.json",
                "description": ", ".join(f"{d}: {n} events" for d, n in sorted(b.events.items())),
            }
        )
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "dataset_id": dataset_id,
        "name": name or dataset_id,
        "provenance": provenance,
        "privacy_class": privacy_class,
        "license": "",
        "usage_constraints": "Operator's own logs. Private; do not publish raw files, windows or models.",
        "description": description or "Built from operator-exported logs with build_dataset.",
        "sources": sources,
        "generator": {
            "module": "ai_threat_detection.experiments.builder",
            "version": BUILDER_VERSION,
            "capture_seconds": bucket_s,
            "gap_seconds": gap_seconds,
            "alignment": "unix_epoch_utc",
            "inputs": stats["inputs"],
            "dropped_in_gap": dict(stats["dropped_in_gap"]),
            "unplaced_unparsed_lines": dict(stats["unplaced"]),
        },
        "label_definition": {
            "unit": "entity-window overlap with labeled interval of the same entity ('*' = all entities)",
            "background": (
                "BENIGN asserted by the operator (not verified)"
                if background == "BENIGN"
                else "UNKNOWN: unlabeled operator logs"
            ),
            "labels_file_sha256": (
                hashlib.sha256(Path(labels_path).read_bytes()).hexdigest() if labels_path else None
            ),
        },
        "captures": captures,
    }
    (root / "dataset.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return {
        "dataset_id": dataset_id,
        "captures": len(captures),
        "events": {d: sum(b.events.get(d, 0) for b in nonempty) for d in sources},
        "dropped_in_gap": dict(stats["dropped_in_gap"]),
        "inputs": stats["inputs"],
    }
