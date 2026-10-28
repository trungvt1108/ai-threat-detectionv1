"""Authentication events, JSON/NDJSON (schema ``atd.auth.v1``).

Kept: time, host, service, source identity, user identity (both pseudonymized),
outcome (SUCCESS / FAILURE / UNKNOWN / MISSING), auth method token and a short
reason token. Passwords, tokens, OTPs and free text are never kept.
A missing outcome is MISSING, never treated as success.
"""

from __future__ import annotations

from typing import Any

from .base import MISSING, Adapter, ParseContext, ParsedEvent, ParseOutcome, pick, short_token

TIME_ALIASES = ("timestamp", "time", "@timestamp", "ts")
HOST_ALIASES = ("host", "hostname")
SERVICE_ALIASES = ("service", "program", "app")
SRC_ALIASES = ("src_ip", "source_ip", "client_ip", "remote_addr", "src", "client_id")
USER_ALIASES = ("user", "username", "account")
OUTCOME_ALIASES = ("outcome", "result", "status")
METHOD_ALIASES = ("auth_method", "method")
REASON_ALIASES = ("reason", "failure_reason")

SUCCESS_WORDS = {"success", "succeeded", "ok", "accepted", "true", "pass", "passed", "allow", "allowed"}
FAILURE_WORDS = {"failure", "failed", "fail", "denied", "rejected", "invalid", "false", "deny", "error"}


def map_outcome(raw: Any) -> str:
    if raw is MISSING or raw is None:
        return "MISSING"
    if isinstance(raw, bool):
        return "SUCCESS" if raw else "FAILURE"
    s = str(raw).strip().lower()
    if s in SUCCESS_WORDS:
        return "SUCCESS"
    if s in FAILURE_WORDS:
        return "FAILURE"
    return "UNKNOWN"


class AuthJsonAdapter(Adapter):
    name = "auth_json"
    schema_version = "atd.auth.v1"
    domains = ("AUTH",)
    supported_fields = {
        "timestamp|time|@timestamp|ts": "ISO 8601 with offset (or epoch); naive needs source assume_timezone",
        "host|hostname": "target host -> pseudonym",
        "service|program|app": "short service token",
        "src_ip|source_ip|client_ip|remote_addr|src|client_id": "source identity -> pseudonym (entity)",
        "user|username|account": "user identity -> pseudonym",
        "outcome|result|status": "success/failure words or boolean; other -> UNKNOWN; absent -> MISSING",
        "auth_method|method": "short token e.g. password, publickey",
        "reason|failure_reason": "short token only (free text dropped)",
    }

    def parse(self, record: dict[str, Any], ctx: ParseContext) -> ParseOutcome:
        pt = self._time(record, TIME_ALIASES, ctx)
        if pt.value is None:
            return ParseOutcome.reject(pt.error or "invalid_timestamp")
        flags = list(pt.flags)
        outcome = map_outcome(pick(record, OUTCOME_ALIASES))
        if outcome == "MISSING":
            flags.append("missing_outcome")
        elif outcome == "UNKNOWN":
            flags.append("unknown_outcome")
        service = short_token(pick(record, SERVICE_ALIASES))
        if service is None:
            flags.append("missing_service")
        fields: dict[str, Any] = {
            "outcome": outcome,
            "service": service,
            "auth_method": short_token(pick(record, METHOD_ALIASES)),
            "reason": short_token(pick(record, REASON_ALIASES)),
        }
        ev = ParsedEvent(
            domain="AUTH",
            schema_version=self.schema_version,
            event_time=pt.value,
            entity_key=None,
            fields=fields,
            quality_flags=flags,
        )
        ev.entity_key = self._identity(ctx, ev, "ip", pick(record, SRC_ALIASES))
        if ev.entity_key is None:
            flags.append("missing_entity")
        ev.user_key = self._identity(ctx, ev, "user", pick(record, USER_ALIASES))
        if ev.user_key is None:
            flags.append("missing_user")
        ev.host_key = self._identity(ctx, ev, "host", pick(record, HOST_ALIASES))
        fields["user_key"] = ev.user_key
        fields["host_key"] = ev.host_key
        if ctx.stable_id_field:
            sid = record.get(ctx.stable_id_field)
            if sid is not None and len(str(sid)) <= 128:
                ev.stable_id = str(sid)
        return ParseOutcome(ev)
