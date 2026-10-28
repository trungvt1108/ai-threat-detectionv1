"""HTTP access log, JSON/NDJSON (schema ``atd.http.v1``).

Kept: time, sensor, client identity (pseudonymized), method, normalized path +
path group, status, response bytes, duration. Dropped: headers, cookies,
bodies, query values, user agent, referer and anything else.
"""

from __future__ import annotations

from typing import Any

from ai_threat_detection.normalization.privacy import normalize_path, scrub_text

from .base import MISSING, Adapter, ParseContext, ParsedEvent, ParseOutcome, as_float, as_int, pick

KNOWN_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"}

TIME_ALIASES = ("timestamp", "time", "@timestamp", "ts")
CLIENT_ALIASES = ("client_ip", "remote_addr", "client", "src_ip", "client_id")
METHOD_ALIASES = ("method", "request_method")
PATH_ALIASES = ("path", "url", "uri", "request_uri")
STATUS_ALIASES = ("status", "status_code")
BYTES_ALIASES = ("bytes", "response_bytes", "body_bytes_sent", "bytes_sent")
DURATION_MS_ALIASES = ("duration_ms", "request_time_ms", "latency_ms")
DURATION_S_ALIASES = ("request_time", "duration_s")
SENSOR_ALIASES = ("sensor", "server", "host")


class HttpJsonAdapter(Adapter):
    name = "http_json"
    schema_version = "atd.http.v1"
    domains = ("HTTP",)
    supported_fields = {
        "timestamp|time|@timestamp|ts": "ISO 8601 with offset (or epoch); naive needs source assume_timezone",
        "client_ip|remote_addr|client|src_ip|client_id": "client identity -> pseudonym (entity)",
        "method|request_method": "HTTP method; unknown values -> OTHER",
        "path|url|uri|request_uri": "normalized: query/fragment/host dropped, ids tokenized",
        "status|status_code": "100-599",
        "bytes|response_bytes|body_bytes_sent|bytes_sent": "response size in bytes",
        "duration_ms|request_time_ms|latency_ms": "milliseconds",
        "request_time|duration_s": "seconds (converted to ms)",
        "sensor|server|host": "sensor/server name (scrubbed, short)",
    }

    def parse(self, record: dict[str, Any], ctx: ParseContext) -> ParseOutcome:
        pt = self._time(record, TIME_ALIASES, ctx)
        if pt.value is None:
            return ParseOutcome.reject(pt.error or "invalid_timestamp")
        flags = list(pt.flags)
        fields: dict[str, Any] = {}

        sensor_raw = pick(record, SENSOR_ALIASES)
        if sensor_raw is MISSING:
            fields["sensor"] = ctx.sensor_default
        else:
            fields["sensor"] = scrub_text(str(sensor_raw), max_len=64)[0]

        method_raw = pick(record, METHOD_ALIASES)
        if method_raw is MISSING:
            fields["method"] = None
            flags.append("missing_method")
        else:
            m = str(method_raw).upper()[:16]
            fields["method"] = m if m in KNOWN_METHODS else "OTHER"

        path_raw = pick(record, PATH_ALIASES)
        np_ = normalize_path(None if path_raw is MISSING else str(path_raw))
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

        status = as_int(pick(record, STATUS_ALIASES), 100, 599)
        fields["status"] = status
        if status is None:
            flags.append("missing_status")

        nbytes = as_int(pick(record, BYTES_ALIASES), 0, 10**13)
        fields["bytes"] = nbytes
        if nbytes is None:
            flags.append("missing_bytes")

        dur = as_float(pick(record, DURATION_MS_ALIASES), 0.0, 3.6e6)
        if dur is None:
            dur_s = as_float(pick(record, DURATION_S_ALIASES), 0.0, 3600.0)
            dur = dur_s * 1000.0 if dur_s is not None else None
        fields["duration_ms"] = round(dur, 3) if dur is not None else None
        if dur is None:
            flags.append("missing_duration")

        ev = ParsedEvent(
            domain="HTTP",
            schema_version=self.schema_version,
            event_time=pt.value,
            entity_key=None,
            fields=fields,
            quality_flags=flags,
        )
        ev.entity_key = self._identity(ctx, ev, "ip", pick(record, CLIENT_ALIASES))
        if ev.entity_key is None:
            flags.append("missing_entity")
        if ctx.stable_id_field:
            sid = record.get(ctx.stable_id_field)
            if sid is not None and len(str(sid)) <= 128:
                ev.stable_id = str(sid)
        return ParseOutcome(ev)
