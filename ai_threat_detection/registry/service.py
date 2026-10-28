"""Model registry: atomic artifact writes, integrity + compatibility checks, activation.

Trust boundary (see docs/THREAT_MODEL.md): artifacts are only loaded from
``<data_dir>/models`` by registry ID, after (1) path containment, (2) SHA-256 match,
(3) HMAC signature with the local integrity key (kept outside DB/Git), (4) dependency
version match and (5) skops type audit against a fixed allowlist. Someone who
controls the key file, the DB and the artifact directory together can still forge a
model; the checks protect against tampering of one of them, accidental mix-ups and
loading arbitrary/uploaded files. The UI/API never accepts a model path or file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import tempfile
import threading
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import numpy as np
import sklearn
import skops
import skops.io as sio
from django.db import transaction
from django.utils import timezone
from sklearn.ensemble import IsolationForest

from ai_threat_detection.conf import get_config
from ai_threat_detection.core.audit import audit
from ai_threat_detection.features.spec import get_feature_set
from ai_threat_detection.normalization.keys import INTEGRITY_KEY, key_id, load_key

from .models import ActivationHistory, ActiveModel, ModelVersion

# Types skops reports as "untrusted" for a fitted IsolationForest. Anything else
# found in an artifact makes the load fail.
TRUSTED_SKOPS_TYPES = frozenset({"sklearn.tree._tree.Tree"})


class ModelLoadError(Exception):
    def __init__(self, status: str, reason: str):
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason


def dependency_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "scikit-learn": sklearn.__version__,
        "numpy": np.__version__,
        "skops": skops.__version__,
    }


def _major_minor(v: str) -> str:
    return ".".join(v.split(".")[:2])


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _signature(key: bytes, model_id: str, sha: str, schema: str, order: list[str]) -> str:
    msg = json.dumps([model_id, sha, schema, order], sort_keys=True).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def models_root() -> Path:
    root = get_config().models_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def write_artifact(model: IsolationForest, model_id: str, domain: str) -> tuple[str, str]:
    """Atomic write: dump to a temp file in the target dir, then os.replace."""
    target_dir = models_root() / domain.lower() / model_id
    target_dir.mkdir(parents=True, exist_ok=False)
    final = target_dir / "model.skops"
    fd, tmp = tempfile.mkstemp(dir=target_dir, suffix=".tmp")
    os.close(fd)
    try:
        sio.dump(model, tmp)
        os.replace(tmp, final)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return final.relative_to(models_root()).as_posix(), _sha256_file(final)


def register_candidate(
    model: IsolationForest, *, domain: str, feature_set: str, fields: dict[str, Any]
) -> ModelVersion:
    fs = get_feature_set(feature_set)
    if fs.domain != domain:
        raise ValueError("feature set domain mismatch")
    stamp = timezone.now().strftime("%Y%m%d%H%M%S")
    model_id = f"{domain.lower()}-if-{stamp}-{os.urandom(3).hex()}"
    rel, sha = write_artifact(model, model_id, domain)
    ikey = load_key(INTEGRITY_KEY)
    mv = ModelVersion.objects.create(
        model_id=model_id,
        domain=domain,
        feature_set=fs.name,
        feature_schema_version=fs.schema_version,
        feature_order=list(fs.features),
        transforms=dict(fs.transforms),
        artifact_rel=rel,
        artifact_sha256=sha,
        artifact_signature=_signature(ikey, model_id, sha, fs.schema_version, list(fs.features)),
        integrity_key_id=key_id(ikey),
        dependencies=dependency_versions(),
        **fields,
    )
    return mv


def _artifact_path(mv: ModelVersion) -> Path:
    root = models_root()
    p = (root / mv.artifact_rel).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        raise ModelLoadError("FAILED", "artifact path outside models directory") from None
    if p.suffix != ".skops":
        raise ModelLoadError("FAILED", "unexpected artifact format")
    return p


def verify_and_load(mv: ModelVersion) -> IsolationForest:
    if mv.artifact_format != "skops":
        raise ModelLoadError("FAILED", "only skops artifacts are loadable")
    try:
        fs = get_feature_set(mv.feature_set)
    except ValueError:
        raise ModelLoadError("INCOMPATIBLE", "feature set unknown to this code version") from None
    if fs.schema_version != mv.feature_schema_version or list(fs.features) != list(mv.feature_order):
        raise ModelLoadError("INCOMPATIBLE", "feature schema/order differs from current code")
    deps = dependency_versions()
    for name in ("scikit-learn", "numpy", "skops"):
        if _major_minor(deps[name]) != _major_minor(mv.dependencies.get(name, "")):
            raise ModelLoadError(
                "INCOMPATIBLE", f"{name} {deps[name]} != trained {mv.dependencies.get(name)}"
            )
    path = _artifact_path(mv)
    if not path.exists():
        raise ModelLoadError("FAILED", "artifact missing")
    sha = _sha256_file(path)
    if sha != mv.artifact_sha256:
        raise ModelLoadError("FAILED", "artifact hash mismatch")
    try:
        ikey = load_key(INTEGRITY_KEY)
    except Exception:  # noqa: BLE001
        raise ModelLoadError("FAILED", "integrity key unavailable") from None
    expected = _signature(ikey, mv.model_id, sha, mv.feature_schema_version, list(mv.feature_order))
    if not hmac.compare_digest(expected, mv.artifact_signature):
        raise ModelLoadError("FAILED", "integrity signature mismatch")
    untrusted = set(sio.get_untrusted_types(file=str(path)))
    if not untrusted <= TRUSTED_SKOPS_TYPES:
        raise ModelLoadError(
            "FAILED", f"artifact contains non-allowlisted types: {sorted(untrusted - TRUSTED_SKOPS_TYPES)}"
        )
    model = sio.load(str(path), trusted=sorted(untrusted))
    if not isinstance(model, IsolationForest):
        raise ModelLoadError("FAILED", "artifact is not an IsolationForest")
    if getattr(model, "n_features_in_", None) != len(mv.feature_order):
        raise ModelLoadError("INCOMPATIBLE", "n_features_in_ mismatch")
    return model


@dataclass
class ActiveDetector:
    domain: str
    status: str  # ACTIVE | STALE | UNTRAINED | INCOMPATIBLE | FAILED
    reason: str
    model_version: ModelVersion | None = None
    model: IsolationForest | None = None

    @property
    def usable(self) -> bool:
        return self.model is not None and self.status in {"ACTIVE", "STALE"}


_cache: dict[tuple[str, str], IsolationForest] = {}
_cache_lock = threading.Lock()


def get_active_detector(domain: str) -> ActiveDetector:
    am = ActiveModel.objects.select_related("model").filter(domain=domain).first()
    if am is None:
        return ActiveDetector(domain, "UNTRAINED", "no active model for domain")
    mv = am.model
    key = (mv.model_id, mv.artifact_sha256)
    with _cache_lock:
        model = _cache.get(key)
    if model is None:
        try:
            model = verify_and_load(mv)
        except ModelLoadError as exc:
            return ActiveDetector(domain, exc.status, exc.reason, mv)
        with _cache_lock:
            _cache.clear()  # keep at most the current models in memory
            _cache[key] = model
    if mv.created_at and timezone.now() - mv.created_at > timedelta(days=get_config().model_max_age_days):
        return ActiveDetector(
            domain, "STALE", f"model older than {get_config().model_max_age_days} days", mv, model
        )
    return ActiveDetector(domain, "ACTIVE", "", mv, model)


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def activate(model_id: str, actor, reason: str, action: str = "ACTIVATE") -> ModelVersion:
    if not reason or len(reason.strip()) < 5:
        raise ValueError("a reason (>= 5 chars) is required")
    mv = ModelVersion.objects.get(model_id=model_id)
    if mv.status not in {"CANDIDATE", "RETIRED", "ACTIVE"}:
        raise ValueError(f"model status {mv.status} cannot be activated")
    if not mv.validation_metrics:
        raise ValueError("model has no validation evaluation; run evaluate_detector first")
    verify_and_load(mv)  # compatibility + integrity gate
    label = actor.get_username() if getattr(actor, "is_authenticated", False) else str(actor or "system")
    with transaction.atomic():
        prev = ActiveModel.objects.filter(domain=mv.domain).select_related("model").first()
        prev_mv = prev.model if prev else None
        if prev_mv and prev_mv.pk != mv.pk:
            ModelVersion.objects.filter(pk=prev_mv.pk).update(status="RETIRED")
        ActiveModel.objects.update_or_create(
            domain=mv.domain,
            defaults={
                "model": mv,
                "reason": reason.strip()[:500],
                "activated_by": actor if getattr(actor, "is_authenticated", False) else None,
            },
        )
        mv.status = "ACTIVE"
        mv.activated_at = timezone.now()
        mv.save(update_fields=["status", "activated_at"])
        ActivationHistory.objects.create(
            domain=mv.domain,
            model=mv,
            previous=prev_mv,
            action=action,
            actor_label=label,
            reason=reason.strip()[:500],
        )
        audit(
            actor,
            f"model.{action.lower()}",
            "model",
            mv.model_id,
            reason,
            previous=prev_mv.model_id if prev_mv else None,
        )
    clear_cache()
    return mv


def rollback(domain: str, actor, reason: str) -> ModelVersion:
    """Re-activate the model that was active before the current one."""
    cur = ActiveModel.objects.filter(domain=domain).select_related("model").first()
    if cur is None:
        raise ValueError("no active model to roll back from")
    hist = ActivationHistory.objects.filter(
        domain=domain, model=cur.model, action__in=["ACTIVATE", "ROLLBACK"]
    ).first()
    if hist is None or hist.previous is None:
        raise ValueError("no previous model recorded for rollback")
    return activate(hist.previous.model_id, actor, reason, action="ROLLBACK")


def deactivate(domain: str, actor, reason: str) -> None:
    """Remove the active model (domain falls back to rules-only, shown as UNTRAINED)."""
    if not reason or len(reason.strip()) < 5:
        raise ValueError("a reason (>= 5 chars) is required")
    with transaction.atomic():
        cur = ActiveModel.objects.filter(domain=domain).select_related("model").first()
        if cur is None:
            return
        ModelVersion.objects.filter(pk=cur.model.pk).update(status="RETIRED")
        ActivationHistory.objects.create(
            domain=domain,
            model=None,
            previous=cur.model,
            action="DEACTIVATE",
            actor_label=getattr(actor, "username", str(actor)),
            reason=reason[:500],
        )
        cur.delete()
        audit(actor, "model.deactivate", "model", cur.model.model_id, reason)
    clear_cache()


def set_threshold(model_id: str, threshold: float, actor, reason: str) -> ModelVersion:
    if not reason or len(reason.strip()) < 5:
        raise ValueError("a reason (>= 5 chars) is required")
    if not (0.0 < threshold <= 1.0):
        raise ValueError("threshold must be in (0, 1] for anomaly_score")
    with transaction.atomic():
        mv = ModelVersion.objects.get(model_id=model_id)
        old = mv.threshold
        mv.threshold = float(threshold)
        mv.threshold_version += 1
        crit = dict(mv.threshold_criterion)
        crit["manual_override"] = {"from": old, "to": threshold, "reason": reason[:300]}
        mv.threshold_criterion = crit
        mv.save(update_fields=["threshold", "threshold_version", "threshold_criterion"])
        ActivationHistory.objects.create(
            domain=mv.domain,
            model=mv,
            previous=mv,
            action="THRESHOLD_CHANGE",
            actor_label=getattr(actor, "username", str(actor)),
            reason=reason[:500],
            details={"from": old, "to": threshold, "threshold_version": mv.threshold_version},
        )
        audit(actor, "model.threshold", "model", model_id, reason, old=old, new=threshold)
    return mv
