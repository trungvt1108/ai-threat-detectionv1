"""TEMPLATE ONLY. Not a claim that this app is production-hardened.

Use as a starting point if you put the console behind a TLS reverse proxy on a
trusted network. Every value must be reviewed; nothing here is deployed by the project.
"""

from __future__ import annotations

import os

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403

SECRET_KEY = os.environ.get("ATD_SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY == "change-me-placeholder":  # noqa: S105 - rejects the placeholder
    raise ImproperlyConfigured("ATD_SECRET_KEY must be set from a secret store")

DEBUG = False
ALLOWED_HOSTS = [h for h in os.environ.get("ATD_ALLOWED_HOSTS", "").split(",") if h]
if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ATD_ALLOWED_HOSTS required")
CSRF_TRUSTED_ORIGINS = [o for o in os.environ.get("ATD_CSRF_TRUSTED_ORIGINS", "").split(",") if o]

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 3600
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
# Only enable if a trusted proxy sets this header and strips it from clients.
if os.environ.get("ATD_TRUST_PROXY_SSL_HEADER") == "1":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
