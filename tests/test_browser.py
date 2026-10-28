"""@browser: real browser (Playwright, system Edge/Chrome channel; no browser download).
Run with: python -m pytest -m browser"""

import os
from pathlib import Path

import pytest

pytestmark = [pytest.mark.browser, pytest.mark.django_db(transaction=True)]
os.environ.setdefault("DJANGO_ALLOW_ASYNC_UNSAFE", "true")


@pytest.fixture
def page():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        browser = None
        for channel in ("msedge", "chrome"):
            try:
                browser = p.chromium.launch(channel=channel, headless=True)
                break
            except Exception:  # noqa: BLE001
                continue
        if browser is None:
            pytest.skip("no local Edge/Chrome channel available for Playwright")
        ctx = browser.new_context(viewport={"width": 1366, "height": 800})
        pg = ctx.new_page()
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        pg.js_errors = errors
        yield pg
        browser.close()


def test_console_flow_in_real_browser(page, live_server, users, make_source, seeded_rules):
    from ai_threat_detection.alerts.detection import run_detection
    from ai_threat_detection.sources.ingest import import_source_file

    from .conftest import T0, auth_rec, write_ndjson

    src = make_source("auth", "auth_json")
    write_ndjson(
        Path(src.root_path) / "a.ndjson",
        [auth_rec(T0, ip="203.0.113.21", user=f"u{i}") for i in range(14)]
        + [auth_rec(T0.replace(hour=13), outcome="success")],
    )
    import_source_file(src, "a.ndjson")
    run_detection("live", "AUTH")

    base = live_server.url
    page.goto(base + "/")
    assert "/login/" in page.url
    page.fill("#id_username", "analyst1")
    page.fill("#id_password", "x-test-password-123")
    page.click("button[type=submit]")
    page.wait_for_url(base + "/")
    assert page.locator("h1").inner_text() == "Tổng quan"
    page.click("nav >> text=Cảnh báo")
    page.wait_for_selector("table")
    page.click("table tbody tr td a")
    page.wait_for_selector("text=AUTH-001")
    page.select_option("#id_to_status", "INVESTIGATING")
    page.select_option("#id_to_assessment", "NEEDS_MORE_EVIDENCE")
    page.fill("#id_note", "checking with account owner")
    page.click("form[action*='triage'] button[type=submit]")
    page.wait_for_selector("text=Đã ghi nhận triage")
    assert page.locator("text=checking with account owner").count() >= 1
    # keyboard focus is visible and the skip link exists
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.className") == "skip"
    # narrow laptop width keeps tables scrollable inside their wrapper (no page-level overflow)
    page.set_viewport_size({"width": 1024, "height": 700})
    overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 1
    page.goto(base + "/experiments/")
    page.goto(base + "/jobs/")
    assert page.js_errors == []


def test_chart_renders_na_for_undefined(page, live_server, users, make_source, seeded_rules):
    """The ES module chart renders bars and shows N/A for undefined metrics (never 0%/100%)."""
    from ai_threat_detection.experiments.models import Dataset, EvaluationRun, Experiment

    ds = Dataset.objects.create(
        dataset_id="d1",
        name="d",
        provenance="SYNTHETIC_DEMO",
        privacy_class="DEMO",
        root_rel="d1",
        manifest_sha256="0" * 64,
    )
    exp = Experiment.objects.create(
        exp_id="e1",
        dataset=ds,
        name="e",
        protocol_version="p",
        window_config={"size_s": 300},
        cfg_hash="x",
        feature_sets={},
    )
    EvaluationRun.objects.create(
        experiment=exp,
        domain="AUTH",
        split="test",
        metrics={
            "tasks": {
                "T1_SUSPICIOUS": {
                    "methods": {"rules_only": {"f1": None}, "ml_only": {"f1": 0.5}, "hybrid_or": {"f1": 0.75}}
                }
            }
        },
    )
    base = live_server.url
    page.goto(base + "/login/")
    page.fill("#id_username", "viewer1")
    page.fill("#id_password", "x-test-password-123")
    page.click("button[type=submit]")
    page.goto(base + "/experiments/e1/")
    page.wait_for_selector(".chart svg")
    txt = page.locator(".chart svg").text_content()
    assert "N/A" in txt and "0.750" in txt
    assert page.js_errors == []
