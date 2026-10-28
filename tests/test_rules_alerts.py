from datetime import timedelta
from pathlib import Path

import pytest
from django.utils import timezone

from ai_threat_detection.alerts.detection import run_detection
from ai_threat_detection.alerts.models import Alert, AlertDecision, Notification, Suppression
from ai_threat_detection.alerts.triage import TriageError, create_suppression, triage
from ai_threat_detection.rules.engine import RuleValidationError, evaluate, parse_rule
from ai_threat_detection.rules.models import RuleConfig, RuleDecision
from ai_threat_detection.rules.service import current_rules, update_rule
from ai_threat_detection.sources.ingest import import_source_file

from .conftest import T0, auth_rec, http_rec, write_ndjson

RULE = {
    "rule_id": "TST-001",
    "domain": "AUTH",
    "name": "t",
    "severity": "medium",
    "conditions": [{"feature": "failures", "op": ">=", "value": 3}],
}


def test_rule_validation_allowlist():
    parse_rule(RULE)
    for bad in (
        {**RULE, "conditions": [{"feature": "__import__('os')", "op": ">=", "value": 1}]},
        {**RULE, "conditions": [{"feature": "failures", "op": "in", "value": 1}]},
        {**RULE, "conditions": [{"feature": "failures", "op": ">=", "value": "1; rm -rf"}]},
        {**RULE, "conditions": [{"feature": "failures", "op": ">=", "value": 1, "expr": "x"}]},
        {**RULE, "eval": "1"},
        {**RULE, "rule_id": "bad id"},
        {**RULE, "domain": "HTTP"},  # failures is not an HTTP feature
        {**RULE, "category": "magic"},
    ):
        with pytest.raises(RuleValidationError):
            parse_rule(bad)


def test_rule_not_evaluable_on_missing_feature():
    r = parse_rule(
        {**RULE, "domain": "HTTP", "conditions": [{"feature": "latency_p95_ms", "op": ">=", "value": 10}]}
    )
    res = evaluate(r, {"latency_p95_ms": None})
    assert res.status == "NOT_EVALUABLE" and res.missing == ["latency_p95_ms"]
    assert evaluate(parse_rule(RULE), {"failures": 3}).status == "TRIGGERED"
    assert evaluate(parse_rule(RULE), {"failures": 2}).status == "NOT_TRIGGERED"


@pytest.mark.django_db
def test_rule_update_creates_version_with_audit(seeded_rules, users):
    from ai_threat_detection.core.models import AuditLog

    rc = RuleConfig.objects.get(rule_id="AUTH-001", is_current=True)
    d = dict(rc.definition)
    d["conditions"] = [
        {"feature": "failures", "op": ">=", "value": 20},
        {"feature": "attempts", "op": ">=", "value": 20},
    ]
    with pytest.raises(RuleValidationError):
        update_rule("AUTH-001", d, True, users["admin"], "")
    new = update_rule("AUTH-001", d, True, users["admin"], "reduce noise from SSO")
    assert new.version == 2 and RuleConfig.objects.filter(rule_id="AUTH-001").count() == 2
    assert [r.version for r in current_rules("AUTH") if r.rule_id == "AUTH-001"] == [2]
    assert AuditLog.objects.filter(action="rule.update", object_id="AUTH-001").exists()


def _burst(src, ip="203.0.113.50", n=15, start=T0):
    recs = [auth_rec(start + timedelta(seconds=5 * i), ip=ip, user=f"u{i % 3}") for i in range(n)]
    recs.append(auth_rec(start + timedelta(minutes=30), ip="198.51.100.1", user="later", outcome="success"))
    write_ndjson(Path(src.root_path) / f"b{start.minute}{n}.ndjson", recs)
    import_source_file(src, f"b{start.minute}{n}.ndjson")


@pytest.mark.django_db
def test_rules_only_fallback_creates_rule_alert_with_evidence_and_versions(make_source, seeded_rules):
    src = make_source("auth", "auth_json")
    _burst(src)
    stats = run_detection("live", "AUTH")
    assert stats["ml_status"] == "UNTRAINED" and stats.get("ml_untrained", 0) >= 1
    a = Alert.objects.get(domain="AUTH")
    assert a.detection_source == "RULE" and "AUTH-001" in a.rule_ids and a.rule_versions["AUTH-001"] == 1
    assert a.max_ml_score is None and a.model_ids == []
    d = a.decisions.get()
    assert d.rule_results[0]["observed"]["failures"] == 15
    assert d.config_snapshot["cfg_hash"] and d.explanation["window"]["events"] == 15
    assert RuleDecision.objects.filter(rule_id="AUTH-001", status="TRIGGERED").exists()
    assert Notification.objects.filter(alert=a).exists()  # medium severity
    assert "đã chiếm" not in a.summary.lower()


@pytest.mark.django_db
def test_grouping_keeps_new_evidence_and_does_not_count_attacks(make_source, seeded_rules):
    src = make_source("auth", "auth_json")
    recs = []
    for w in range(3):  # three consecutive bursting windows of the same entity
        recs += [auth_rec(T0 + timedelta(minutes=5 * w, seconds=5 * i), ip="203.0.113.60") for i in range(12)]
    recs.append(auth_rec(T0 + timedelta(hours=1), ip="198.51.100.1", outcome="success"))
    write_ndjson(Path(src.root_path) / "g.ndjson", recs)
    import_source_file(src, "g.ndjson")
    run_detection("live", "AUTH")
    assert Alert.objects.count() == 1
    a = Alert.objects.get()
    assert a.decision_count == 3 and AlertDecision.objects.filter(alert=a).count() == 3
    assert a.window_end - a.window_start == timedelta(minutes=15)


@pytest.mark.django_db
def test_suppression_scoped_expiring_and_visible(make_source, seeded_rules, users):
    src = make_source("auth", "auth_json")
    from ai_threat_detection.normalization.pseudonym import Pseudonymizer

    key = Pseudonymizer.from_local_key().pseudonym("ip", "203.0.113.70")
    with pytest.raises(TriageError):
        create_suppression(users["analyst"], domain="AUTH", reason="too short", days=3)
    with pytest.raises(TriageError):
        create_suppression(
            users["analyst"], domain="AUTH", entity_key=key, reason="known pentest box", days=90
        )
    s = create_suppression(
        users["analyst"], domain="AUTH", entity_key=key, reason="authorized password audit host", days=1
    )
    _burst(src, ip="203.0.113.70")
    run_detection("live", "AUTH")
    a = Alert.objects.get(entity_key=key)
    assert a.suppressed and a.suppression_id == s.pk
    assert not Notification.objects.filter(alert=a).exists()
    Suppression.objects.filter(pk=s.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
    _burst(src, ip="203.0.113.70", start=T0 + timedelta(hours=3))
    run_detection("live", "AUTH")
    assert Alert.objects.filter(entity_key=key, suppressed=False).count() == 1


@pytest.mark.django_db
def test_triage_workflow_rules(make_source, seeded_rules, users):
    src = make_source("auth", "auth_json")
    _burst(src)
    run_detection("live", "AUTH")
    a = Alert.objects.get()
    assert a.workflow_status == "NEW" and a.assessment == "NEEDS_REVIEW"
    with pytest.raises(TriageError):
        triage(a, users["analyst"], "CLOSED", "NEEDS_REVIEW", "")
    with pytest.raises(TriageError):
        triage(a, users["analyst"], "ACKNOWLEDGED", "FALSE_POSITIVE", "")  # assessment change needs a note
    triage(a, users["analyst"], "INVESTIGATING", "FALSE_POSITIVE", "SSO gateway retry storm")
    a.refresh_from_db()
    assert a.workflow_status == "INVESTIGATING" and a.triage.count() == 1
    triage(a, users["analyst"], "CLOSED", "FALSE_POSITIVE", "")
    assert a.triage.last().actor_label == "analyst1"


@pytest.mark.django_db
def test_health_alert_for_parser_failures(make_source, seeded_rules):
    from ai_threat_detection.alerts.health import evaluate_ingest_health

    src = make_source()
    write_ndjson(Path(src.root_path) / "bad.ndjson", [http_rec(T0)] * 15, raw_lines=["{bad"] * 10)
    run = import_source_file(src, "bad.ndjson")
    assert evaluate_ingest_health(run) == ["HLTH-001"]
    a = Alert.objects.get(domain="HEALTH")
    assert a.detection_source == "DATA_QUALITY" and a.entity_key == f"source:{src.name}"


@pytest.mark.django_db
def test_upstream_ids_alerts_are_labelled_upstream(make_source, seeded_rules):
    from ai_threat_detection.alerts.detection import process_upstream_ids

    src = make_source("eve", "suricata_eve", file_pattern="*.json")
    rec = {
        "timestamp": "2026-05-04T10:00:00.000000+0000",
        "event_type": "alert",
        "flow_id": 9,
        "src_ip": "203.0.113.8",
        "dest_ip": "192.0.2.1",
        "proto": "TCP",
        "alert": {"signature_id": 1, "signature": "TEST sig", "severity": 1},
    }
    write_ndjson(Path(src.root_path) / "eve.json", [rec, {**rec, "event_type": "stats"}])
    run = import_source_file(src, "eve.json")
    assert run.reject_reasons == {"unsupported_event_type": 1}
    out = process_upstream_ids("live")
    a = Alert.objects.get(detection_source="UPSTREAM_IDS")
    assert (
        out["upstream_alerts_created"] == 1
        and a.severity == "high"
        and "không phải phát hiện của model" in a.summary
    )
    assert process_upstream_ids("live")["upstream_alerts_created"] == 0
    with pytest.raises(ValueError):
        run_detection("live", "EVE_FLOW")
