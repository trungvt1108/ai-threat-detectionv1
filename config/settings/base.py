"""Shared Django settings. Environment-specific modules import from here."""

from __future__ import annotations

from ai_threat_detection.conf import REPO_ROOT, get_config

ATD = get_config()
BASE_DIR = REPO_ROOT

DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "ai_threat_detection.core",
    "ai_threat_detection.accounts",
    "ai_threat_detection.sources",
    "ai_threat_detection.features",
    "ai_threat_detection.rules",
    "ai_threat_detection.registry",
    "ai_threat_detection.experiments",
    "ai_threat_detection.alerts",
    "ai_threat_detection.worker",
    "ai_threat_detection.reports",
    "ai_threat_detection.ui",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "ai_threat_detection.core.middleware.CrossSiteBlockMiddleware",
    "ai_threat_detection.core.middleware.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "ai_threat_detection.ui.context.console_context",
            ],
            "autoescape": True,
        },
    }
]


def sqlite_database(path: str) -> dict:
    """SQLite with WAL + busy timeout + IMMEDIATE write transactions.

    WAL lets the UI read while the worker writes; IMMEDIATE avoids lock upgrade
    deadlocks between concurrent writers (worker + UI mutations).
    """
    return {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": path,
        "OPTIONS": {
            "timeout": 20,
            "transaction_mode": "IMMEDIATE",
            "init_command": "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
        },
    }


DATABASES = {"default": sqlite_database(str(ATD.db_path))}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "vi"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = str(ATD.data_dir / "staticfiles")

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_AGE = 8 * 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

DATA_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = 200

MESSAGE_STORAGE = "django.contrib.messages.storage.session.SessionStorage"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"redact": {"()": "ai_threat_detection.normalization.privacy.RedactingLogFilter"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "filters": ["redact"]}},
    "root": {"handlers": ["console"], "level": "WARNING"},
    "loggers": {
        "ai_threat_detection": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False},
    },
}

# Windows can map .js/.css to wrong MIME types via the registry; ES modules need text/javascript.
import mimetypes  # noqa: E402

mimetypes.add_type("text/javascript", ".js", strict=True)
mimetypes.add_type("text/css", ".css", strict=True)
