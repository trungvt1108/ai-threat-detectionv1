"""Test fixtures. Everything runs offline against a temporary ATD_DATA_DIR created by
config.settings.test; no user logs, no network (except loopback in @lab tests)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ai_threat_detection.conf import get_config
from ai_threat_detection.normalization.keys import INTEGRITY_KEY, PSEUDONYM_KEY, create_key

T0 = datetime(2026, 5, 4, 10, 0, tzinfo=UTC)


@pytest.fixture(scope="session", autouse=True)
def _keys():
    cfg = get_config()
    for d in cfg.managed_dirs():
        d.mkdir(parents=True, exist_ok=True)
    create_key(PSEUDONYM_KEY)
    create_key(INTEGRITY_KEY)
    yield


@pytest.fixture
def inbox() -> Path:
    p = get_config().inbox_dir
    p.mkdir(parents=True, exist_ok=True)
    return p


def iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def write_ndjson(
    path: Path, records: list, raw_lines: list[str] | None = None, newline_end: bool = True
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(r) if not isinstance(r, str) else r for r in records]
    if raw_lines:
        lines += raw_lines
    path.write_text("\n".join(lines) + ("\n" if newline_end else ""), encoding="utf-8", newline="\n")
    return path


def http_rec(
    t: datetime, ip: str = "198.51.100.7", path: str = "/", status: int = 200, method: str = "GET", **kw
):
    r = {
        "timestamp": iso(t),
        "client_ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "bytes": 1200,
        "duration_ms": 12.5,
    }
    r.update(kw)
    return r


def auth_rec(t: datetime, ip: str = "198.51.100.9", user: str = "alice", outcome: str = "failure", **kw):
    r = {
        "timestamp": iso(t),
        "src_ip": ip,
        "user": user,
        "outcome": outcome,
        "service": "webapp",
        "host": "auth-01",
    }
    r.update(kw)
    return r


@pytest.fixture
def make_source(db, inbox):
    from ai_threat_detection.sources.models import Source

    def _make(name="src-http", stype="http_json", sub="", **kw):
        root = inbox / f"{sub or name}-{uuid.uuid4().hex[:8]}"
        root.mkdir(parents=True, exist_ok=False)
        return Source.objects.create(name=name, source_type=stype, root_path=str(root), **kw)

    return _make


@pytest.fixture
def users(db):
    from django.contrib.auth import get_user_model

    from ai_threat_detection.accounts.roles import set_role

    out = {}
    for role in ("admin", "analyst", "viewer"):
        u = get_user_model().objects.create_user(username=f"{role}1", password="x-test-password-123")
        set_role(u, role)
        out[role] = u
    out["norole"] = get_user_model().objects.create_user(username="norole", password="x-test-password-123")
    return out


@pytest.fixture
def seeded_rules(db):
    from ai_threat_detection.rules.service import ensure_default_rules

    ensure_default_rules()


def window_cfg(size=60, stride=None, lateness=10, min_events=1):
    from ai_threat_detection.features.spec import WindowConfig

    return WindowConfig(
        size_s=size, stride_s=stride or size, allowed_lateness_s=lateness, min_events=min_events
    )


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)
