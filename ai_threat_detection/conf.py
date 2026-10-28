"""Runtime configuration read from ATD_* environment variables.

Values here are budgets and locations only. Secrets (Django key, pseudonymization
key, artifact integrity key) live in files under ``<data_dir>/keys`` created by
``manage.py init_local`` and are never stored in the database or Git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _int(name: str, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{name} out of range")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AtdConfig:
    data_dir: Path
    allowed_source_roots: tuple[Path, ...]
    max_cpu_threads: int
    max_line_bytes: int
    max_file_bytes: int
    max_json_array_bytes: int
    max_events_per_job: int
    import_chunk: int
    max_events_per_window: int
    retention_days: int
    model_max_age_days: int
    allow_raw_identity_view: bool
    public_identity_allowlist: tuple[str, ...]
    max_upload_bytes: int
    job_stale_seconds: int
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    @property
    def models_dir(self) -> Path:
        return self.data_dir / "models"

    @property
    def datasets_dir(self) -> Path:
        return self.data_dir / "datasets"

    @property
    def experiments_dir(self) -> Path:
        return self.data_dir / "experiments"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def public_drafts_dir(self) -> Path:
        return self.data_dir / "public_drafts"

    @property
    def lab_dir(self) -> Path:
        return self.data_dir / "lab"

    @property
    def inbox_dir(self) -> Path:
        return self.data_dir / "inbox"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "db" / "atd.sqlite3"

    def managed_dirs(self) -> list[Path]:
        return [
            self.keys_dir,
            self.models_dir,
            self.datasets_dir,
            self.experiments_dir,
            self.reports_dir,
            self.public_drafts_dir,
            self.lab_dir,
            self.inbox_dir,
            self.db_path.parent,
        ]


def _load() -> AtdConfig:
    data_dir_raw = os.environ.get("ATD_DATA_DIR", "").strip()
    data_dir = Path(data_dir_raw).resolve() if data_dir_raw else (REPO_ROOT / ".local")
    roots_raw = os.environ.get("ATD_ALLOWED_SOURCE_ROOTS", "").strip()
    if roots_raw:
        roots = tuple(Path(p).resolve() for p in roots_raw.split(os.pathsep) if p.strip())
    else:
        roots = (data_dir / "lab", data_dir / "datasets", data_dir / "inbox")
    allow = tuple(
        s.strip().lower() for s in os.environ.get("ATD_PUBLIC_IDENTITY_ALLOWLIST", "").split(",") if s.strip()
    )
    return AtdConfig(
        data_dir=data_dir,
        allowed_source_roots=roots,
        max_cpu_threads=_int("ATD_MAX_CPU_THREADS", 2, 1, 16),
        max_line_bytes=_int("ATD_MAX_LINE_BYTES", 64 * 1024, 256, 4 * 1024 * 1024),
        max_file_bytes=_int("ATD_MAX_FILE_BYTES", 2 * 1024**3, 1024),
        max_json_array_bytes=_int("ATD_MAX_JSON_ARRAY_BYTES", 64 * 1024**2, 1024),
        max_events_per_job=_int("ATD_MAX_EVENTS_PER_JOB", 2_000_000, 10),
        import_chunk=_int("ATD_IMPORT_CHUNK", 2000, 10, 50_000),
        max_events_per_window=_int("ATD_MAX_EVENTS_PER_WINDOW", 200_000, 100),
        retention_days=_int("ATD_RETENTION_DAYS", 30, 1, 3650),
        model_max_age_days=_int("ATD_MODEL_MAX_AGE_DAYS", 90, 1, 3650),
        allow_raw_identity_view=_bool("ATD_ALLOW_RAW_IDENTITY_VIEW", False),
        public_identity_allowlist=allow,
        max_upload_bytes=_int("ATD_MAX_UPLOAD_BYTES", 20 * 1024**2, 1024),
        job_stale_seconds=_int("ATD_JOB_STALE_SECONDS", 300, 10),
    )


@lru_cache(maxsize=1)
def get_config() -> AtdConfig:
    return _load()


def reset_config_cache() -> None:
    get_config.cache_clear()
