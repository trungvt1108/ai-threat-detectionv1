"""Test settings: isolated temporary data dir, ephemeral keys, in-file SQLite."""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="atd-test-"))
os.environ["ATD_DATA_DIR"] = str(_tmp)
os.environ.setdefault(
    "ATD_ALLOWED_SOURCE_ROOTS",
    os.pathsep.join([str(_tmp / "inbox"), str(_tmp / "lab"), str(_tmp / "datasets")]),
)

from ai_threat_detection.conf import reset_config_cache  # noqa: E402

reset_config_cache()

from .base import *  # noqa: E402,F403
from .base import sqlite_database  # noqa: E402

SECRET_KEY = secrets.token_urlsafe(50)
DEBUG = False
ALLOWED_HOSTS = ["testserver", "127.0.0.1", "localhost"]
CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:8815", "http://localhost:8815"]
DATABASES = {"default": sqlite_database(str(_tmp / "db" / "test.sqlite3"))}
DATABASES["default"]["TEST"] = {"NAME": str(_tmp / "db" / "test.sqlite3")}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # speed only; tests never ship
(_tmp / "db").mkdir(parents=True, exist_ok=True)
