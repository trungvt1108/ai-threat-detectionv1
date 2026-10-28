"""HTTP access log, text: NCSA common / combined format (nginx and Apache defaults).

    203.0.113.5 - - [28/Oct/2026:09:00:01 +0700] "GET /login?x=1 HTTP/1.1" 200 512 "ref" "ua"

Produces the same canonical fields as ``http_json`` (schema ``atd.http.v1``).
Kept: client (pseudonymized), time, method, normalized path, status, bytes,
and the request duration only when the line carries ``rt=`` / ``request_time=``
(seconds). Dropped: remote user (``%u``), protocol, query values, referer, user
agent and any other trailing fields.

Without a duration the ``http_v1`` feature set abstains (``INSUFFICIENT_DATA``);
train such sources with the ``http_v1_core`` feature set.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from ai_threat_detection.normalization.privacy import normalize_path
from ai_threat_detection.normalization.timeparse import MAX_YEAR, MIN_YEAR

from .base import ParseContext, ParsedEvent, ParseOutcome, TextAdapter
from .http_json import KNOWN_METHODS

LINE_RE = re.compile(
    r"^(?P<client>\S{1,256}) \S+ \S+ \[(?P<time>[^\]]{1,40})\] "
    r'"(?P<request>(?:[^"\\]|\\.){0,8192})" (?P<status>\d{3}|-) (?P<bytes>\d{1,15}|-)(?P<rest>.*)$'
)
TIME_RE = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
DURATION_RE = re.compile(r"(?:^|\s)(?:rt|request_time)=(\d{1,7}(?:\.\d{1,6})?)(?=\s|$)")
MONTHS = {m: i for i, m in enumerate(("jan feb mar apr may jun jul aug sep oct nov dec").split(), start=1)}


def parse_clf_time(raw: str) -> datetime | None:
    """``28/Oct/2026:09:00:01 +0700`` -> aware UTC datetime. Locale-independent."""
    m = TIME_RE.match(raw)
    if not m:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    month = MONTHS.get(mon.lower())
    if month is None:
        return None
    offset = timedelta(hours=int(oh), minutes=int(om))
    try:
        tz = timezone(offset if sign == "+" else -offset)
        dt = datetime(int(year), month, int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    except ValueError:
        return None
    return dt.astimezone(UTC)


class HttpCombinedAdapter(TextAdapter):
    name = "http_combined"
    schema_version = "atd.http.v1"
    domains = ("HTTP",)
    supported_fields = {
        "%h": "client address -> pseudonym (entity)",
        "%t": "[dd/Mon/yyyy:HH:MM:SS +zzzz] (offset required by the format)",
        '"%r"': "method + target: path normalized, query values/fragment dropped, protocol dropped",
        "%>s": "status 100-599",
        "%b": "response bytes ('-' means 0 bytes, per the CLF definition)",
        "rt=|request_time=": "optional trailing key, seconds (converted to ms)",
        "%l %u referer user-agent, other trailing fields": "dropped",
    }

    def parse(self, record: dict[str, Any], ctx: ParseContext) -> ParseOutcome:
        m = LINE_RE.match(record["line"])
        if not m:
            return ParseOutcome.reject("unrecognized_access_line")
        when = parse_clf_time(m.group("time"))
        if when is None:
            return ParseOutcome.reject("invalid_timestamp")
        if not (MIN_YEAR <= when.year <= MAX_YEAR):
            return ParseOutcome.reject("implausible_timestamp")
        flags: list[str] = []
        fields: dict[str, Any] = {"sensor": ctx.sensor_default}

        parts = m.group("request").split(" ")
        if len(parts) in (2, 3) and parts[0].isalpha() and parts[1]:
            method = parts[0].upper()[:16]
            fields["method"] = method if method in KNOWN_METHODS else "OTHER"
            target = parts[1]
        else:
            # Empty ("-") or garbage request lines, typical of scanners and TLS-on-plain-port probes.
            fields["method"] = "OTHER"
            flags.append("malformed_request_line")
            target = None
        np_ = normalize_path(target)
        if np_ is None:
            fields["path"] = None
            fields["path_group"] = None
            flags.append("missing_path")
        else:
            fields["path"] = np_.path
            fields["path_group"] = np_.path_group
            fields["had_query"] = np_.had_query
            fields["query_param_count"] = np_.query_param_count
            flags.extend(np_.flags)

        status_raw = m.group("status")
        status = int(status_raw) if status_raw != "-" else None
        if status is not None and not 100 <= status <= 599:
            status = None
        fields["status"] = status
        if status is None:
            flags.append("missing_status")

        bytes_raw = m.group("bytes")
        fields["bytes"] = 0 if bytes_raw == "-" else int(bytes_raw)

        dm = DURATION_RE.search(m.group("rest"))
        dur = float(dm.group(1)) * 1000.0 if dm else None
        if dur is not None and dur > 3.6e6:
            dur = None
        fields["duration_ms"] = round(dur, 3) if dur is not None else None
        if dur is None:
            flags.append("missing_duration")

        ev = ParsedEvent(
            domain="HTTP",
            schema_version=self.schema_version,
            event_time=when,
            entity_key=None,
            fields=fields,
            quality_flags=flags,
        )
        client = m.group("client")
        ev.entity_key = self._identity(ctx, ev, "ip", None if client == "-" else client)
        if ev.entity_key is None:
            flags.append("missing_entity")
        return ParseOutcome(ev)
