"""SSH authentication from syslog text (``/var/log/auth.log``, ``/var/log/secure``,
``journalctl -o short-iso``). Produces the ``atd.auth.v1`` canonical fields.

Accepted line prefixes:

* RFC 3339 (rsyslog high precision, Ubuntu 24.04+ default, journalctl short-iso)::

    2026-10-28T09:00:01.123456+07:00 web1 sshd[812]: Failed password for root from 203.0.113.5 port 52314 ssh2

* Traditional BSD syslog (no year, no zone)::

    Oct 28 09:00:01 web1 sshd[812]: Accepted publickey for alice from 198.51.100.7 port 50022 ssh2

  It requires the source's ``assume_timezone``; the year is inferred from the
  ingest time (previous year when the date would lie more than a day in the
  future) and flagged ``year_inferred``.

Only ``sshd`` / ``sshd-session`` / ``sshd-auth`` "Accepted ..." and "Failed ..."
decisions become events. Other programs (cron, sudo, systemd, ...) and other
sshd messages are *skipped*, not rejected: they are out of scope, not parse
failures. ``Invalid user X from ...`` notices are skipped because OpenSSH logs a
``Failed ... for invalid user X`` line for the same attempt when a credential is
tried. rsyslog's ``message repeated N times: [ ... ]`` is counted once and
flagged ``repeated_message_collapsed`` (the true count is not recoverable as
separate events). Passwords never appear in these lines; nothing else is kept.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ai_threat_detection.normalization.timeparse import parse_timestamp

from .base import ParseContext, ParsedEvent, ParseOutcome, TextAdapter

PROG = r"(?P<prog>[A-Za-z0-9_./-]{1,64})(?:\[(?P<pid>\d{1,10})\])?: (?P<msg>.*)$"
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S{1,255}) " + PROG
)
BSD_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2}) (?P<host>\S{1,255}) " + PROG
)
REPEATED_RE = re.compile(r"^message repeated (\d{1,9}) times: \[ ?(.*?) ?\]$")
DECISION_RE = re.compile(
    r"^(?P<res>Accepted|Failed) (?P<meth>[A-Za-z0-9/_-]{1,40}) for (?P<invalid>invalid user )?"
    r"(?P<user>.{0,256}?) from (?P<ip>[0-9A-Fa-f:.]{2,45}) port \d{1,5}(?: ssh2)?(?:: .*)?$"
)
SSHD_PROGRAMS = {"sshd", "sshd-session", "sshd-auth"}
MONTHS = {m: i for i, m in enumerate(("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec").split(), start=1)}
FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def _bsd_time(m: re.Match[str], tz_name: str | None, now: datetime) -> tuple[datetime | None, str | None]:
    if not tz_name:
        return None, "missing_timezone"
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        return None, "invalid_assumed_timezone"
    month = MONTHS.get(m.group("mon"))
    if month is None:
        return None, "invalid_timestamp"
    hh, mm, ss = (int(x) for x in m.group("hms").split(":"))
    year = now.astimezone(tz).year
    for y in (year, year - 1):
        try:
            dt = datetime(y, month, int(m.group("day")), hh, mm, ss, tzinfo=tz).astimezone(UTC)
        except ValueError:
            return None, "invalid_timestamp"
        if dt <= now + timedelta(days=1):
            return dt, None
    return None, "invalid_timestamp"


class AuthSyslogAdapter(TextAdapter):
    name = "auth_syslog"
    schema_version = "atd.auth.v1"
    domains = ("AUTH",)
    supported_fields = {
        "timestamp": "RFC 3339 prefix, or 'Mon dd HH:MM:SS' with source assume_timezone (year inferred)",
        "hostname": "syslog host -> pseudonym",
        "program": "only sshd / sshd-session / sshd-auth lines are used; others are skipped",
        "Accepted <method> for <user> from <ip>": "outcome SUCCESS",
        "Failed <method> for [invalid user ]<user> from <ip>": "outcome FAILURE; reason invalid_user or invalid_credentials",
        "user / ip": "pseudonymized (user, entity)",
    }

    def parse(self, record: dict[str, Any], ctx: ParseContext) -> ParseOutcome:
        line = record["line"]
        flags: list[str] = []
        m = ISO_RE.match(line)
        if m:
            ts = FRACTION_RE.sub(r"\1", m.group("ts"))
            pt = parse_timestamp(ts, ctx.assume_timezone)
            if pt.value is None:
                return ParseOutcome.reject(pt.error or "invalid_timestamp")
            when = pt.value
            flags.extend(pt.flags)
        else:
            m = BSD_RE.match(line)
            if not m:
                return ParseOutcome.reject("unrecognized_syslog_line")
            parsed, err = _bsd_time(m, ctx.assume_timezone, ctx.reference_time or datetime.now(UTC))
            if parsed is None:
                return ParseOutcome.reject(err or "invalid_timestamp")
            when = parsed
            flags.extend(["tz_assumed", "year_inferred"])

        if m.group("prog") not in SSHD_PROGRAMS:
            return ParseOutcome.skip("not_sshd")
        msg = m.group("msg").strip()
        rep = REPEATED_RE.match(msg)
        if rep:
            msg = rep.group(2)
            flags.append("repeated_message_collapsed")
        if msg.startswith("Invalid user "):
            return ParseOutcome.skip("invalid_user_notice")
        d = DECISION_RE.match(msg)
        if not d:
            return ParseOutcome.skip("sshd_other_message")

        success = d.group("res") == "Accepted"
        if success:
            reason = None
        else:
            reason = "invalid_user" if d.group("invalid") else "invalid_credentials"
        fields: dict[str, Any] = {
            "outcome": "SUCCESS" if success else "FAILURE",
            "service": "sshd",
            "auth_method": d.group("meth").lower().replace("/", "-")[:40],
            "reason": reason,
        }
        ev = ParsedEvent(
            domain="AUTH",
            schema_version=self.schema_version,
            event_time=when,
            entity_key=None,
            fields=fields,
            quality_flags=flags,
        )
        ev.entity_key = self._identity(ctx, ev, "ip", d.group("ip"))
        if ev.entity_key is None:
            flags.append("missing_entity")
        ev.user_key = self._identity(ctx, ev, "user", d.group("user").strip() or None)
        if ev.user_key is None:
            flags.append("missing_user")
        ev.host_key = self._identity(ctx, ev, "host", m.group("host"))
        fields["user_key"] = ev.user_key
        fields["host_key"] = ev.host_key
        return ParseOutcome(ev)
