"""Dataset manifests, capture import into per-capture namespaces, and label sidecars.

Layout under ``<data_dir>/datasets/<dataset_id>/``::

    dataset.json                       manifest (provenance, privacy, license, captures,
                                       optional per-domain "sources": {type, assume_timezone})
    captures/<capture_id>/http.ndjson  raw capture as emitted by the generator / fixture
    captures/<capture_id>/auth.ndjson  (text formats, e.g. http.log / auth.log, via "sources")
    captures/<capture_id>/labels.json  label intervals from the controlled schedule

Labels never enter event fields or features; they are resolved against windows
only at evaluation time (entity selectors are pseudonymized with the same key).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from django.db import transaction

from ai_threat_detection.conf import get_config
from ai_threat_detection.normalization.pseudonym import Pseudonymizer
from ai_threat_detection.normalization.timeparse import parse_timestamp, validate_timezone
from ai_threat_detection.sources.adapters.registry import get_adapter
from ai_threat_detection.sources.ingest import IngestOptions, import_source_file
from ai_threat_detection.sources.models import PrivacyClass, Provenance, Source

from .models import Capture, Dataset

DOMAIN_FILES = {"HTTP": ("http", "http_json"), "AUTH": ("auth", "auth_json")}
VALID_LABELS = {"SUSPICIOUS_PATTERN", "OPERATIONAL_ANOMALY", "AUTHORIZED_LOAD", "BENIGN"}
MANIFEST_VERSION = "atd.dataset.v1"


class DatasetError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def dataset_dir(dataset_id: str) -> Path:
    return get_config().datasets_dir / dataset_id


def _contained(base: Path, rel: str) -> Path:
    p = (base / rel).resolve()
    p.relative_to(base.resolve())
    return p


def register_dataset(dataset_id: str, actor=None) -> Dataset:
    base = dataset_dir(dataset_id)
    mpath = base / "dataset.json"
    if not mpath.exists():
        raise DatasetError("dataset.json not found")
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != MANIFEST_VERSION or manifest.get("dataset_id") != dataset_id:
        raise DatasetError("manifest version/id mismatch")
    if (
        manifest.get("provenance") not in Provenance.values
        or manifest.get("privacy_class") not in PrivacyClass.values
    ):
        raise DatasetError("invalid provenance/privacy_class")
    for dom, spec in (manifest.get("sources") or {}).items():
        _check_source_spec(dom, spec)
    with transaction.atomic():
        ds, created = Dataset.objects.get_or_create(
            dataset_id=dataset_id,
            defaults=dict(
                name=manifest.get("name", dataset_id)[:200],
                provenance=manifest["provenance"],
                privacy_class=manifest["privacy_class"],
                license=manifest.get("license", "")[:200],
                usage_constraints=manifest.get("usage_constraints", "")[:500],
                description=manifest.get("description", ""),
                root_rel=base.relative_to(get_config().datasets_dir).as_posix(),
                manifest_sha256=sha256_file(mpath),
                generator=manifest.get("generator", {}),
                label_definition=manifest.get("label_definition", {}),
                created_by=actor if getattr(actor, "is_authenticated", False) else None,
            ),
        )
        if not created:
            if ds.manifest_sha256 != sha256_file(mpath):
                raise DatasetError(
                    "dataset already registered with a different manifest; use a new dataset_id"
                )
            return ds
        for c in manifest["captures"]:
            files = {}
            for dom, rel in c["files"].items():
                p = _contained(base, rel)
                if not p.exists():
                    raise DatasetError(f"missing capture file {rel}")
                files[dom] = {"rel": rel, "sha256": sha256_file(p), "bytes": p.stat().st_size}
            lp = _contained(base, c["labels"])
            start = parse_timestamp(c["start"]).value
            end = parse_timestamp(c["end"]).value
            if start is None or end is None or end <= start:
                raise DatasetError("invalid capture time range")
            Capture.objects.create(
                dataset=ds,
                capture_id=c["capture_id"],
                scenario_group=c.get("scenario_group", c["capture_id"]),
                start=start,
                end=end,
                files=files,
                labels_rel=c["labels"],
                labels_sha256=sha256_file(lp),
                background_label=json.loads(lp.read_text(encoding="utf-8")).get(
                    "background_label", "UNKNOWN"
                ),
                namespace=f"ds:{dataset_id}/{c['capture_id']}",
                description=c.get("description", "")[:300],
            )
    return ds


def _check_source_spec(domain: str, spec: Any) -> dict[str, Any]:
    if domain not in DOMAIN_FILES or not isinstance(spec, dict):
        raise DatasetError(f"invalid source spec for domain {domain!r}")
    stype = spec.get("type", DOMAIN_FILES[domain][1])
    try:
        adapter = get_adapter(stype)
    except ValueError as exc:
        raise DatasetError(str(exc)) from None
    if domain not in adapter.domains:
        raise DatasetError(f"source type {stype} does not produce {domain} events")
    tz = spec.get("assume_timezone") or ""
    if tz and not validate_timezone(tz):
        raise DatasetError(f"unknown timezone {tz!r}")
    return {"type": stype, "assume_timezone": tz, "pattern": adapter.default_pattern}


def _manifest_sources(ds: Dataset) -> dict[str, Any]:
    mpath = dataset_dir(ds.dataset_id) / "dataset.json"
    if sha256_file(mpath) != ds.manifest_sha256:
        raise DatasetError("dataset.json changed since registration")
    return json.loads(mpath.read_text(encoding="utf-8")).get("sources") or {}


def _dataset_source(ds: Dataset, domain: str) -> Source:
    prefix, _default_type = DOMAIN_FILES[domain]
    spec = _check_source_spec(domain, _manifest_sources(ds).get(domain, {}))
    name = f"ds-{ds.dataset_id}-{prefix}"[:64]
    src, _ = Source.objects.get_or_create(
        name=name,
        defaults=dict(
            source_type=spec["type"],
            root_path=str(dataset_dir(ds.dataset_id).resolve()),
            file_pattern=spec["pattern"],
            assume_timezone=spec["assume_timezone"],
            provenance=ds.provenance,
            privacy_class=ds.privacy_class,
            sensor_name=f"dataset-{ds.dataset_id}"[:64],
            license_note=ds.license[:500],
            usage_constraints=ds.usage_constraints[:500],
        ),
    )
    return src


def import_dataset(ds: Dataset, ctx=None, job_id=None) -> dict[str, Any]:
    """Verify file hashes, then import each capture file into its own namespace.

    Health rules (parse failure ratio, gaps) run on every capture import, exactly
    as for ``import_logs``, so degraded logging inside a dataset is visible.
    """
    from ai_threat_detection.alerts.health import evaluate_ingest_health

    base = dataset_dir(ds.dataset_id)
    stats: dict[str, Any] = {}
    for cap in ds.captures.all():
        cstats = {}
        for dom, info in cap.files.items():
            p = _contained(base, info["rel"])
            if sha256_file(p) != info["sha256"]:
                raise DatasetError(f"capture file hash changed: {info['rel']}")
            src = _dataset_source(ds, dom)
            run = import_source_file(
                src,
                info["rel"],
                IngestOptions(namespace=cap.namespace, capture_id=cap.capture_id, mode="IMPORT"),
                ctx=ctx,
                job_id=job_id,
            )
            cstats[dom] = {
                "accepted": run.accepted,
                "duplicates": run.duplicates,
                "rejected": run.rejected,
                "skipped": run.skipped,
                "reject_reasons": run.reject_reasons,
                "quality_flags": run.quality_flag_counts,
                "max_event_gap_seconds": run.max_event_gap_seconds,
                "health_alerts": evaluate_ingest_health(run),
            }
        cap.imported = True
        cap.import_stats = cstats
        cap.save(update_fields=["imported", "import_stats"])
        stats[cap.capture_id] = cstats
    ds.status = "IMPORTED"
    ds.pseudonym_key_id = Pseudonymizer.from_local_key().key_id
    ds.save(update_fields=["status", "pseudonym_key_id"])
    return stats


def load_intervals(cap: Capture) -> tuple[list[dict[str, Any]], str]:
    """Resolve label intervals; entity selectors are pseudonymized with the dataset source scope."""
    base = dataset_dir(cap.dataset.dataset_id)
    lp = _contained(base, cap.labels_rel)
    if sha256_file(lp) != cap.labels_sha256:
        raise DatasetError("labels file changed since registration")
    data = json.loads(lp.read_text(encoding="utf-8"))
    out = []
    for iv in data.get("intervals", []):
        label = iv["label"]
        if label not in VALID_LABELS:
            raise DatasetError(f"invalid label {label}")
        dom = iv["domain"]
        src = _dataset_source(cap.dataset, dom)
        ps = Pseudonymizer.from_local_key(scope=src.pseudonym_scope)
        ent = iv["entity"]
        key = "*" if ent == "*" else ps.pseudonym(ent["kind"], ent["value"])
        s = parse_timestamp(iv["start"]).value
        e = parse_timestamp(iv["end"]).value
        if s is None or e is None:
            raise DatasetError("invalid interval time")
        out.append(
            {
                "domain": dom,
                "entity_key": key,
                "start": s,
                "end": e,
                "label": label,
                "scenario": iv.get("scenario"),
                "instance": iv.get("instance"),
            }
        )
    bg = data.get("background_label", "UNKNOWN")
    if bg not in VALID_LABELS | {"UNKNOWN"}:
        raise DatasetError("invalid background label")
    return out, bg


def manifest_summary(ds: Dataset) -> dict[str, Any]:
    return {
        "dataset_id": ds.dataset_id,
        "provenance": ds.provenance,
        "privacy_class": ds.privacy_class,
        "license": ds.license,
        "manifest_sha256": ds.manifest_sha256,
        "captures": [
            {
                "capture_id": c.capture_id,
                "group": c.scenario_group,
                "start": c.start.isoformat(),
                "end": c.end.isoformat(),
                "files": {k: {"sha256": v["sha256"], "bytes": v["bytes"]} for k, v in c.files.items()},
                "labels_sha256": c.labels_sha256,
            }
            for c in ds.captures.all()
        ],
    }


def iso(dt: datetime) -> str:
    return dt.isoformat()
