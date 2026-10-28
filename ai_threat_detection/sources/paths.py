"""Filesystem boundary checks. Sources can only read inside explicitly allowed roots."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from ai_threat_detection.conf import get_config


class PathNotAllowedError(ValueError):
    pass


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_source_root(root: str) -> Path:
    if not root or "\x00" in root:
        raise PathNotAllowedError("empty or invalid path")
    p = Path(root).resolve()
    allowed = [r.resolve() for r in get_config().allowed_source_roots]
    if not any(_within(p, a) for a in allowed):
        raise PathNotAllowedError("root is outside ATD_ALLOWED_SOURCE_ROOTS")
    return p


def resolve_source_file(root: str, file_rel: str, pattern: str) -> Path:
    base = validate_source_root(root)
    if not file_rel or "\x00" in file_rel or Path(file_rel).is_absolute() or file_rel.startswith(("\\", "/")):
        raise PathNotAllowedError("file must be a relative path inside the source root")
    candidate = (base / file_rel).resolve()
    if not _within(candidate, base):
        raise PathNotAllowedError("file escapes the source root")
    if not fnmatch.fnmatch(candidate.name, pattern) and not fnmatch.fnmatch(candidate.name, pattern + ".*"):
        raise PathNotAllowedError("file name does not match the source pattern")
    return candidate


def list_source_files(root: str, pattern: str, limit: int = 500) -> list[str]:
    base = validate_source_root(root)
    if not base.is_dir():
        return []
    out = []
    for p in sorted(base.rglob(pattern)):
        if p.is_file() and _within(p.resolve(), base):
            out.append(p.relative_to(base).as_posix())
            if len(out) >= limit:
                break
    return out
