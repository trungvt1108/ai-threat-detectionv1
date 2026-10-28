"""@lab: starts the project fixture service on 127.0.0.1 and drives real HTTP requests.
Run with: python -m pytest -m lab"""

import json

import pytest

from ai_threat_detection.conf import get_config

pytestmark = [pytest.mark.lab, pytest.mark.django_db]


def test_lab_smoke_capture_import_and_redaction(seeded_rules):
    from ai_threat_detection.experiments.datasets import import_dataset, register_dataset
    from ai_threat_detection.lab.capture import run_lab_capture
    from ai_threat_detection.sources.models import Event

    res = run_lab_capture("lab-smoke-t", profile="smoke", seed=11)
    assert res["captures"] == 3 and res["requests"] > 20
    root = get_config().datasets_dir / "lab-smoke-t"
    raw = (root / "captures" / "c00" / "http.ndjson").read_text(encoding="utf-8")
    assert '"client_id":"lab-client-1"' in raw  # the fixture really logged the driver's requests
    labels = json.loads((root / "captures" / "c01" / "labels.json").read_text(encoding="utf-8"))
    assert labels["intervals"][0]["scenario"] == "auth_burst"
    ds = register_dataset("lab-smoke-t")
    assert ds.provenance == "LAB_OBSERVED" and ds.privacy_class == "LAB"
    stats = import_dataset(ds)
    assert stats["c00"]["HTTP"]["accepted"] > 0
    fields = json.dumps([e.fields for e in Event.objects.filter(namespace__startswith="ds:lab-smoke-t/")])
    assert "session=lab" not in fields and "request_headers" not in fields  # careless cookie logging stripped
    auth = Event.objects.filter(namespace="ds:lab-smoke-t/c01", domain="AUTH")
    assert auth.filter(fields__outcome="FAILURE").count() >= 3


def test_driver_refuses_non_fixture_urls():
    from ai_threat_detection.lab.capture import FixtureTarget

    t = FixtureTarget.__new__(FixtureTarget)
    t.base = "http://127.0.0.1:1"
    for bad in ("http://example.com/", "//evil/", "https://x"):
        with pytest.raises(ValueError):
            t.url(bad)
