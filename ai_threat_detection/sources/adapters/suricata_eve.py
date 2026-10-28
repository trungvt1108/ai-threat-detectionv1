"""Suricata EVE JSON adapter: ``alert`` and ``flow`` event types only.

Field subset written against the Suricata 7.0.x EVE output documentation
(common fields + ``alert`` + ``flow`` objects); the same names exist in 6.0.x.
Other event types (dns, http, tls, fileinfo, stats, anomaly, ...) are counted as
``unsupported_event_type`` rather than silently dropped.

Scope: import / correlation / enrichment only.
* EVE ``alert`` events are UPSTREAM IDS signals. They are never presented as
  detections of this project's models, and alert/signature fields are never used
  as ML features or as labels for evaluating the project's detectors.
* EVE ``flow`` events have no model in v1 (status UPSTREAM_ONLY).
* ``flow_id`` is only meaningful within one sensor; correlation keys carry the
  sensor name and are never assumed to match flow IDs from other sources.
Payload, packet, payload_printable, http bodies, TLS certificates, files and
metadata are not stored.
"""

from __future__ import annotations

from typing import Any

from ai_threat_detection.normalization.privacy import scrub_text

from .base import MISSING, Adapter, ParseContext, ParsedEvent, ParseOutcome, as_int, pick, short_token

EVE_FORMAT_REFERENCE = "suricata-eve-7.0 (alert, flow subset)"
SUPPORTED_EVENT_TYPES = {"alert", "flow"}


class SuricataEveAdapter(Adapter):
    name = "suricata_eve"
    schema_version = "atd.eve.v1"
    domains = ("EVE_ALERT", "EVE_FLOW")
    supported_fields = {
        "timestamp": "ISO 8601 with offset, e.g. 2024-01-01T00:00:00.000000+0000",
        "event_type": "alert | flow (others counted as unsupported)",
        "flow_id": "sensor-local id; correlation key = sensor:flow_id",
        "in_iface, proto, app_proto, community_id": "short tokens",
        "src_ip/dest_ip": "pseudonymized (entity = src)",
        "src_port/dest_port": "0-65535",
        "alert.{action,gid,signature_id,rev,signature,category,severity}": "upstream IDS metadata",
        "flow.{pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,start,end,age,state,reason,alerted}": "flow stats",
    }

    def parse(self, record: dict[str, Any], ctx: ParseContext) -> ParseOutcome:
        et = record.get("event_type")
        if not isinstance(et, str):
            return ParseOutcome.reject("missing_event_type")
        if et not in SUPPORTED_EVENT_TYPES:
            return ParseOutcome.reject("unsupported_event_type")
        pt = self._time(record, ("timestamp",), ctx)
        if pt.value is None:
            return ParseOutcome.reject(pt.error or "invalid_timestamp")
        flags = list(pt.flags)
        sensor = ctx.sensor_default
        host_raw = record.get("host")
        if isinstance(host_raw, str) and host_raw:
            sensor = scrub_text(host_raw, max_len=64)[0]
        flow_id = as_int(record.get("flow_id"), 0, 2**64)
        fields: dict[str, Any] = {
            "event_type": et,
            "sensor": sensor,
            "flow_id": flow_id,
            "correlation_key": f"{sensor}:{flow_id}" if flow_id is not None else None,
            "in_iface": short_token(record.get("in_iface"), 32),
            "proto": short_token(record.get("proto"), 16),
            "app_proto": short_token(record.get("app_proto"), 32),
            "community_id": (
                str(record["community_id"])[:64] if isinstance(record.get("community_id"), str) else None
            ),
            "src_port": as_int(record.get("src_port"), 0, 65535),
            "dest_port": as_int(record.get("dest_port"), 0, 65535),
            "eve_format_reference": EVE_FORMAT_REFERENCE,
        }
        if et == "alert":
            alert = record.get("alert")
            if not isinstance(alert, dict):
                return ParseOutcome.reject("alert_object_missing")
            sig = alert.get("signature")
            fields["upstream_alert"] = {
                "action": short_token(alert.get("action"), 16),
                "gid": as_int(alert.get("gid"), 0, 2**32),
                "signature_id": as_int(alert.get("signature_id"), 0, 2**32),
                "rev": as_int(alert.get("rev"), 0, 2**32),
                "signature": scrub_text(sig, max_len=200)[0] if isinstance(sig, str) else None,
                "category": scrub_text(alert["category"], max_len=100)[0]
                if isinstance(alert.get("category"), str)
                else None,
                "severity": as_int(alert.get("severity"), 1, 255),
            }
            domain = "EVE_ALERT"
        else:
            flow = record.get("flow")
            if not isinstance(flow, dict):
                return ParseOutcome.reject("flow_object_missing")
            fields["flow"] = {
                "pkts_toserver": as_int(flow.get("pkts_toserver"), 0, 2**63),
                "pkts_toclient": as_int(flow.get("pkts_toclient"), 0, 2**63),
                "bytes_toserver": as_int(flow.get("bytes_toserver"), 0, 2**63),
                "bytes_toclient": as_int(flow.get("bytes_toclient"), 0, 2**63),
                "start": flow.get("start") if isinstance(flow.get("start"), str) else None,
                "end": flow.get("end") if isinstance(flow.get("end"), str) else None,
                "age": as_int(flow.get("age"), 0, 10**9),
                "state": short_token(flow.get("state"), 16),
                "reason": short_token(flow.get("reason"), 16),
                "alerted": flow.get("alerted") if isinstance(flow.get("alerted"), bool) else None,
            }
            domain = "EVE_FLOW"
        ev = ParsedEvent(
            domain=domain,
            schema_version=self.schema_version,
            event_time=pt.value,
            entity_key=None,
            fields=fields,
            quality_flags=flags,
        )
        ev.entity_key = self._identity(ctx, ev, "ip", pick(record, ("src_ip",)))
        if ev.entity_key is None:
            flags.append("missing_entity")
        dst = pick(record, ("dest_ip",))
        ev.peer_key = self._identity(ctx, ev, "ip", dst) if dst is not MISSING else None
        fields["peer_key"] = ev.peer_key
        if ctx.stable_id_field:
            sid = record.get(ctx.stable_id_field)
            if sid is not None and len(str(sid)) <= 128:
                ev.stable_id = str(sid)
        return ParseOutcome(ev)
