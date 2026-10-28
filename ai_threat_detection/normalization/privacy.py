"""Redaction applied before anything from a source record is persisted.

Strategy is allowlist-first: adapters copy only named fields. This module adds a
second layer that scrubs secret-looking values from the few free-text fields we
keep (e.g. Suricata signature text) and normalizes URL paths so query strings,
fragments and identifiers never reach storage.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field

SENSITIVE_KEY_RE = re.compile(
    r"(authorization|cookie|set-cookie|session|jwt|token|passw|pwd|secret|api[_-]?key|apikey|"
    r"credential|private[_-]?key|otp|mfa|bearer|signature_sig|x-amz-|auth)",
    re.IGNORECASE,
)

_SECRET_VALUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    ),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{2,}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")),
    ("basic_auth", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{6,}")),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "kv_secret",
        re.compile(
            r"(?i)\b(password|passwd|pwd|pass|token|secret|api[_-]?key|access[_-]?key|session(?:id)?|sid|auth)"
            r"\s*[=:]\s*([^&\s;,\"']+)"
        ),
    ),
    ("url_userinfo", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")),
]

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUM_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{12,}$")
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_\-+=.~]{24,}$")
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._\-~]{1,64}$")

MAX_PATH_SEGMENTS = 12


def scrub_text(value: str, max_len: int = 256) -> tuple[str, list[str]]:
    """Replace secret-looking substrings. Returns (clean_text, kinds_found)."""
    found: list[str] = []
    out = value
    for kind, pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(out):
            found.append(kind)
            if kind == "kv_secret":
                out = pattern.sub(lambda m: f"{m.group(1)}=[REDACTED]", out)
            elif kind == "url_userinfo":
                out = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]@", out)
            else:
                out = pattern.sub(f"[REDACTED:{kind}]", out)
    if _EMAIL_RE.search(out):
        found.append("email")
        out = _EMAIL_RE.sub("[REDACTED:email]", out)
    out = "".join(ch if ch.isprintable() else "?" for ch in out)
    if len(out) > max_len:
        out = out[:max_len] + "…"
    return out, found


@dataclass
class NormalizedPath:
    path: str
    path_group: str
    had_query: bool
    query_param_count: int
    flags: list[str] = field(default_factory=list)


def _norm_segment(seg: str) -> str:
    if not seg:
        return seg
    if _NUM_RE.match(seg):
        return "{num}"
    if _UUID_RE.match(seg):
        return "{uuid}"
    if _HEX_RE.match(seg):
        return "{hex}"
    if "@" in seg and _EMAIL_RE.search(seg):
        return "{email}"
    if _TOKENISH_RE.match(seg) and any(c.isdigit() for c in seg):
        return "{token}"
    if not _SAFE_SEGMENT_RE.match(seg):
        return "{other}"
    return seg


def normalize_path(raw: str | None) -> NormalizedPath | None:
    """Drop scheme/host/userinfo/query/fragment, tokenize identifier-like segments.

    Query *values* are never kept; only the count of parameters survives.
    """
    if raw is None:
        return None
    s = str(raw)
    flags: list[str] = []
    if len(s) > 4096:
        s = s[:4096]
        flags.append("path_truncated")
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*", s)
    if m:
        s = s[m.end() :] or "/"
        flags.append("absolute_url_stripped")
    frag = s.find("#")
    if frag >= 0:
        s = s[:frag]
    q = s.find("?")
    had_query = q >= 0
    qcount = 0
    if had_query:
        query = s[q + 1 :]
        qcount = len([p for p in query.split("&") if p])
        s = s[:q]
    if not s.startswith("/"):
        s = "/" + s
    segments = [seg for seg in s.split("/")]
    norm = [_norm_segment(seg) for seg in segments[1:]]
    if len(norm) > MAX_PATH_SEGMENTS:
        norm = norm[:MAX_PATH_SEGMENTS] + ["{more}"]
        flags.append("path_segments_truncated")
    path = "/" + "/".join(norm)
    group = "/" + (norm[0] if norm and norm[0] else "")
    return NormalizedPath(
        path=path, path_group=group, had_query=had_query, query_param_count=qcount, flags=flags
    )


def sanitized_preview(raw: bytes, max_len: int = 120) -> str:
    """A short, scrubbed preview of an invalid line. Only used when explicitly enabled per source."""
    text = raw[: max_len * 2].decode("utf-8", errors="replace")
    text, _ = scrub_text(text, max_len=max_len)
    # Mask anything that looks like an IP so previews don't leak identities either.
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[ip]", text)
    return text


def content_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class RedactingLogFilter(logging.Filter):
    """Scrub secrets from application log messages; never echo full inputs."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - malformed log args must not crash logging
            msg = str(record.msg)
        clean, found = scrub_text(msg, max_len=2000)
        if found:
            record.msg = clean
            record.args = ()
        return True
