"""Adapter contract: one untrusted bounded line -> allowlisted canonical fields.

JSON adapters decode a line with ``json.loads`` only; text adapters match a
fixed regular expression. Nothing is eval'd, exec'd or deserialized beyond
that. Unknown fields are dropped, not stored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ai_threat_detection.normalization.pseudonym import Pseudonymizer
from ai_threat_detection.normalization.timeparse import parse_timestamp

MISSING = object()


@dataclass
class ParseContext:
    pseudonymizer: Pseudonymizer
    assume_timezone: str | None = None
    sensor_default: str = "default"
    stable_id_field: str | None = None
    capture_raw_identity: bool = False
    # "Now" for formats without a year (BSD syslog); None = wall clock at parse time.
    reference_time: datetime | None = None


@dataclass
class ParsedEvent:
    domain: str
    schema_version: str
    event_time: datetime
    entity_key: str | None
    fields: dict[str, Any]
    quality_flags: list[str] = field(default_factory=list)
    user_key: str | None = None
    host_key: str | None = None
    peer_key: str | None = None
    stable_id: str | None = None
    raw_identities: dict[str, tuple[str, str]] = field(default_factory=dict)


@dataclass
class ParseOutcome:
    event: ParsedEvent | None = None
    reject_reason: str | None = None
    # A well-formed line that is out of scope for this adapter (not a parse failure).
    skip_reason: str | None = None

    @classmethod
    def reject(cls, reason: str) -> ParseOutcome:
        return cls(None, reason)

    @classmethod
    def skip(cls, reason: str) -> ParseOutcome:
        return cls(None, None, reason)


def pick(record: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for name in aliases:
        if name in record and record[name] is not None and record[name] != "":
            return record[name]
    return MISSING


def as_int(value: Any, lo: int, hi: int) -> int | None:
    if value is MISSING or value is None or isinstance(value, bool):
        return None
    try:
        iv = int(float(value)) if isinstance(value, str | float) else int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if iv < lo or iv > hi:
        return None
    return iv


def as_float(value: Any, lo: float, hi: float) -> float | None:
    if value is MISSING or value is None or isinstance(value, bool):
        return None
    try:
        fv = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if fv != fv or fv < lo or fv > hi:  # NaN check
        return None
    return fv


def short_token(value: Any, max_len: int = 40) -> str | None:
    """Accept only short enum-like tokens (a-z, 0-9, _ - .)."""
    if value is MISSING or value is None:
        return None
    s = str(value).strip().lower()
    if not s or len(s) > max_len:
        return None
    if not all(c.isalnum() or c in "_-." for c in s):
        return None
    return s


class Adapter:
    name: str = ""
    schema_version: str = ""
    domains: tuple[str, ...] = ()
    supported_fields: dict[str, str] = {}
    line_format: str = "json"  # "json" (object per line or JSON array) or "text"
    default_pattern: str = "*.ndjson"

    def decode_line(self, data: bytes, is_first: bool) -> tuple[dict[str, Any] | None, str | None]:
        """Returns (record, None), (None, reject_reason) or (None, None) for a blank line."""
        from ai_threat_detection.sources.reader import decode_json_object

        return decode_json_object(data, is_first)

    def parse(self, record: dict[str, Any], ctx: ParseContext) -> ParseOutcome:  # pragma: no cover
        raise NotImplementedError

    def _time(self, record: dict[str, Any], aliases: tuple[str, ...], ctx: ParseContext):
        raw = pick(record, aliases)
        return parse_timestamp(None if raw is MISSING else raw, ctx.assume_timezone)

    def _identity(self, ctx: ParseContext, ev: ParsedEvent, kind: str, raw: Any) -> str | None:
        if raw is MISSING or raw is None:
            return None
        s = str(raw).strip()
        if not s or len(s) > 256:
            return None
        pseudo = ctx.pseudonymizer.pseudonym(kind, s)
        if pseudo and ctx.capture_raw_identity:
            ev.raw_identities[pseudo] = (kind, s)
        return pseudo


class TextAdapter(Adapter):
    """Base for line-oriented text logs. ``parse`` receives ``{"line": <str>}``."""

    line_format = "text"
    default_pattern = "*"

    def decode_line(self, data: bytes, is_first: bool) -> tuple[dict[str, Any] | None, str | None]:
        if is_first and data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        data = data.rstrip(b"\r")
        if not data.strip():
            return None, None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None, "invalid_utf8"
        return {"line": text}, None
