"""Timestamp parsing with explicit timezone policy.

* Offset-aware ISO 8601 (incl. 'Z' and Suricata's '+0000') -> converted to UTC.
* Epoch seconds/milliseconds (numbers) -> UTC by definition, flagged ``epoch_ts``.
* Naive timestamps are rejected unless the source config declares
  ``assume_timezone``; then they are localized and flagged ``tz_assumed``.
* Implausible years are rejected rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MIN_YEAR = 2000
MAX_YEAR = 2100


@dataclass
class ParsedTime:
    value: datetime | None
    error: str | None = None
    flags: list[str] = field(default_factory=list)


def validate_timezone(name: str) -> bool:
    try:
        ZoneInfo(name)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return False


def parse_timestamp(raw: object, assume_timezone: str | None = None) -> ParsedTime:
    if raw is None or raw == "":
        return ParsedTime(None, "missing_timestamp")
    flags: list[str] = []
    if isinstance(raw, bool):
        return ParsedTime(None, "invalid_timestamp")
    if isinstance(raw, int | float):
        secs = float(raw)
        if secs > 1e12:
            secs /= 1000.0
            flags.append("epoch_ms")
        try:
            dt = datetime.fromtimestamp(secs, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return ParsedTime(None, "invalid_timestamp")
        flags.append("epoch_ts")
    elif isinstance(raw, str):
        s = raw.strip()
        if len(s) > 64:
            return ParsedTime(None, "invalid_timestamp")
        if s.endswith("Z") or s.endswith("z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return ParsedTime(None, "invalid_timestamp")
        if dt.tzinfo is None:
            if not assume_timezone:
                return ParsedTime(None, "missing_timezone")
            try:
                dt = dt.replace(tzinfo=ZoneInfo(assume_timezone))
            except (ZoneInfoNotFoundError, ValueError):
                return ParsedTime(None, "invalid_assumed_timezone")
            flags.append("tz_assumed")
        dt = dt.astimezone(UTC)
    else:
        return ParsedTime(None, "invalid_timestamp")
    if not (MIN_YEAR <= dt.year <= MAX_YEAR):
        return ParsedTime(None, "implausible_timestamp")
    return ParsedTime(dt, None, flags)
