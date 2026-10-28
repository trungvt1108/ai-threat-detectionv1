"""Local single-analyst settings. Binds to loopback only (see QUICKSTART)."""

from __future__ import annotations

import os

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403
from .base import ATD


def _secret_key() -> str:
    env = os.environ.get("ATD_SECRET_KEY", "").strip()
    if env and env != "change-me-placeholder":
        return env
    path = ATD.keys_dir / "django_secret.key"
    if path.exists():
        return path.read_text(encoding="ascii").strip()
    # Allowed only so `manage.py init_local` can run once to create the key file.
    return ""


SECRET_KEY = _secret_key()
if not SECRET_KEY and os.environ.get("ATD_ALLOW_MISSING_SECRET") != "1":
    import sys

    if len(sys.argv) < 2 or sys.argv[1] not in {"init_local", "doctor", "help", "--help"}:
        raise ImproperlyConfigured("Missing secret key. Run: python manage.py init_local")
    import secrets

    SECRET_KEY = secrets.token_urlsafe(50)  # ephemeral, only for init_local/doctor before the key file exists

DEBUG = os.environ.get("ATD_DEBUG", "").lower() in {"1", "true"}
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:8815", "http://localhost:8815"]

# Serve app static files from runserver without DEBUG (local console only; see config/urls.py).
ATD_SERVE_STATIC = True
