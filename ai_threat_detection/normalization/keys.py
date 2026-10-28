"""Local key files (pseudonymization, artifact integrity, Django secret).

Keys are random bytes stored hex-encoded under ``<data_dir>/keys``. They are never
written to the DB, Git, reports or exports. Only a non-reversible key ID
(first 12 hex chars of SHA-256 of the key) is recorded in manifests so that a key
change is detectable.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from ai_threat_detection.conf import get_config

PSEUDONYM_KEY = "pseudonym.key"
INTEGRITY_KEY = "integrity.key"
DJANGO_KEY = "django_secret.key"


class KeyMissingError(RuntimeError):
    pass


def key_path(name: str) -> Path:
    env_name = {PSEUDONYM_KEY: "ATD_PSEUDONYM_KEY_FILE", INTEGRITY_KEY: "ATD_INTEGRITY_KEY_FILE"}.get(name)
    if env_name and os.environ.get(env_name):
        return Path(os.environ[env_name]).resolve()
    return get_config().keys_dir / name


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows ACLs are not changed by chmod; documented in OPERATIONS.md


def create_key(name: str) -> tuple[Path, bool]:
    """Create a key file if absent. Returns (path, created). Never overwrites."""
    path = key_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path, False
    value = secrets.token_urlsafe(64) if name == DJANGO_KEY else secrets.token_hex(32)
    with open(path, "x", encoding="ascii") as fh:
        fh.write(value)
    _restrict(path)
    return path, True


def load_key(name: str) -> bytes:
    path = key_path(name)
    if not path.exists():
        raise KeyMissingError(f"Key file '{name}' missing. Run: python manage.py init_local")
    raw = path.read_text(encoding="ascii").strip()
    if name == DJANGO_KEY:
        return raw.encode()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise KeyMissingError(f"Key file '{name}' is not valid hex") from exc
    if len(key) < 32:
        raise KeyMissingError(f"Key file '{name}' too short")
    return key


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"atd-key-id\x00" + key).hexdigest()[:12]


def key_status(name: str) -> dict[str, str]:
    try:
        return {"name": name, "status": "PRESENT", "key_id": key_id(load_key(name))}
    except KeyMissingError as exc:
        return {"name": name, "status": "MISSING", "detail": str(exc)}
