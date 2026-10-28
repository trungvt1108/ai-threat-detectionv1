import json
from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from ai_threat_detection.conf import get_config
from ai_threat_detection.experiments.metrics import binary_metrics, evaluate_units, window_label
from ai_threat_detection.experiments.models import EvaluationRun
from ai_threat_detection.experiments.service import (
    ProtocolError,
    assign_splits,
    check_temporal_gaps,
    evaluate_test,
)
from ai_threat_detection.features.models import FeatureWindow

T = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def small_experiment(django_db_setup, django_db_blocker):
    """A real (small) synthetic dataset -> import -> experiment -> AUTH/HTTP models (session scoped)."""
    from ai_threat_detection.demo.synthetic import generate_dataset
    from ai_threat_detection.experiments.datasets import import_dataset, register_dataset
    from ai_threat_detection.experiments.service import create_experiment, train_detector
    from ai_threat_detection.features.spec import WindowConfig
    from ai_threat_detection.rules.service import ensure_default_rules

    with django_db_blocker.unblock():
        ensure_default_rules()
        generate_dataset("t-small", seed=99, n_captures=6, hours=1.0)
        ds = register_dataset("t-small")
        import_dataset(ds)
        ds.refresh_from_db()
        exp = create_experiment(
            ds,
            "t-small-exp",
            "t",
            WindowConfig(size_s=300, stride_s=300, allowed_lateness_s=60),
            counts=(3, 1, 2),
        )
        models = {d: train_detector(exp, d) for d in ("AUTH", "HTTP")}
        yield {"dataset": ds, "experiment": exp, "models": models}
        from django.core.management import call_command

        call_command("flush", interactive=False, verbosity=0)


class C:
    def __init__(self, cid, group, day):
        self.capture_id, self.scenario_group = cid, group
        self.start = T + timedelta(days=day)
        self.end = self.start + timedelta(hours=1)


def test_split_is_chronological_by_group_and_groups_never_split():
    caps = [C("a", "g1", 0), C("b", "g1", 1), C("c", "g2", 2), C("d", "g3", 3), C("e", "g4", 4)]
    a = assign_splits(caps, (2, 1, 1))
    assert a == {"a": "train", "b": "train", "c": "train", "d": "validation", "e": "test"}
    with pytest.raises(ProtocolError):
        assign_splits(caps[:2], None)


def test_purge_gap_enforced():
    caps = [C("a", "a", 0), C("b", "b", 1), C("c", "c", 2)]
    caps[1].start = caps[0].end + timedelta(seconds=100)
    with pytest.raises(ProtocolError):
        check_temporal_gaps(caps, {"a": "train", "b": "validation", "c": "test"}, timedelta(seconds=360))
    caps[1].start = caps[0].end + timedelta(seconds=400)
    check_temporal_gaps(caps, {"a": "train", "b": "validation", "c": "test"}, timedelta(seconds=360))


def test_binary_metrics_undefined_are_none_not_zero_or_hundred():
    m = binary_metrics([0, 0, 0], [0, 0, 0])
    assert m["precision"] is None and m["recall"] is None and m["f1"] is None and m["support_positive"] == 0
    m = binary_metrics([1, 0], [0, 0])
    assert m["precision"] is None and m["recall"] == 0.0 and m["f1"] is None
    m = binary_metrics([1, 0, 1, 0], [1, 1, 0, 0])
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["tp"] == 1 and m["fp"] == 1
    assert binary_metrics([], [])["precision"] is None


def u(label, rule_t=False, rule_any=False, ml=None, thr=0.5, ent="e1", minute=0, scenario=None):
    s = T + timedelta(minutes=minute)
    return {
        "label": label,
        "scenario": scenario,
        "instance": scenario,
        "entity": ent,
        "start": s,
        "end": s + timedelta(minutes=5),
        "rule_hit_threat": rule_t,
        "rule_hit_any": rule_any or rule_t,
        "ml_status": "SCORED" if ml is not None else "INSUFFICIENT_DATA",
        "ml_score": ml,
        "ml_hit": ml is not None and ml >= thr,
    }


def test_evaluate_units_tasks_unknown_and_grouping():
    units = [
        u("SUSPICIOUS_PATTERN", rule_t=True, ml=0.7, minute=0, scenario="burst"),
        u("SUSPICIOUS_PATTERN", ml=0.6, minute=5, scenario="burst"),
        u("OPERATIONAL_ANOMALY", rule_any=True, ml=0.4, ent="e2"),
        u("BENIGN", ml=0.3, ent="e3"),
        u("BENIGN", ml=None, ent="e4"),
        u("UNKNOWN", rule_t=True, ml=0.9, ent="e5"),
    ]
    r1 = evaluate_units(units, "T1_SUSPICIOUS", 2.0, timedelta(minutes=15))
    assert r1["units_excluded_unknown_label"] == 1
    m = r1["methods"]
    assert m["rules_only"]["tp"] == 1 and m["rules_only"]["fp"] == 0  # operational rule not counted in T1
    assert m["ml_only"]["tp"] == 2 and m["ml_only"]["fn"] == 0
    assert m["ml_only"]["grouped_alerts"]["total"] == 1  # two consecutive windows -> one grouped alert
    assert r1["ml_ranking"]["abstained_windows"] == 1 and r1["ml_ranking"]["value"] == 1.0
    assert m["hybrid_or"]["per_scenario"]["burst"]["instances_flagged"] == 1
    r2 = evaluate_units(units, "T2_ANOMALOUS", 2.0, timedelta(minutes=15))
    assert r2["methods"]["rules_only"]["tp"] == 2  # operational rule counts in T2
    only_neg = [u("BENIGN", ml=0.1)]
    assert (
        evaluate_units(only_neg, "T1_SUSPICIOUS", 1.0, timedelta(minutes=15))["ml_ranking"]["value"] is None
    )


def test_window_label_precedence_and_entity_star():
    s, e = T, T + timedelta(minutes=5)
    ivs = [
        {
            "domain": "HTTP",
            "entity_key": "*",
            "start": s,
            "end": e,
            "label": "OPERATIONAL_ANOMALY",
            "scenario": "o",
        },
        {
            "domain": "HTTP",
            "entity_key": "x",
            "start": s,
            "end": e,
            "label": "SUSPICIOUS_PATTERN",
            "scenario": "s",
        },
    ]
    assert window_label("HTTP", "x", s, e, ivs, "BENIGN")[0] == "SUSPICIOUS_PATTERN"
    assert window_label("HTTP", "y", s, e, ivs, "BENIGN")[0] == "OPERATIONAL_ANOMALY"
    assert window_label("HTTP", "y", e, e + timedelta(minutes=5), ivs, "BENIGN")[0] == "BENIGN"  # half-open
    assert window_label("AUTH", "x", s, e, ivs, "UNKNOWN")[0] == "UNKNOWN"


@pytest.mark.django_db
def test_small_end_to_end_experiment(small_experiment):
    exp = small_experiment["experiment"]
    manifest = json.loads((get_config().experiments_dir / exp.split_manifest_rel).read_text(encoding="utf-8"))
    for dom in ("AUTH", "HTTP"):
        d = manifest["diagnostics"][dom]
        assert (
            d["window_overlap_train_test"] == 0
            and d["window_overlap_train_val"] == 0
            and d["capture_overlap"] == 0
        )
        assert set(manifest["counts"]["train"][dom]) == {"BENIGN"}
    for mv in small_experiment["models"].values():
        assert mv.status == "CANDIDATE" and mv.n_train >= 20
        assert mv.validation_metrics["save_load_max_abs_score_diff"] == 0.0
        assert mv.threshold_criterion["selected_on"].startswith("validation")
        # reference/baseline come from train windows only
        assert mv.train_exclusions["train_labels_used"] == ["BENIGN"]
    mv = small_experiment["models"]["HTTP"]
    run = evaluate_test(exp, "HTTP", mv)
    assert not run.test_previously_seen
    t1 = run.metrics["tasks"]["T1_SUSPICIOUS"]
    assert t1["methods"]["rules_only"]["support_total"] == t1["methods"]["ml_only"]["support_total"]
    assert (
        run.metrics["timing"]["ml_windows_per_second"] is None
        or run.metrics["timing"]["ml_windows_per_second"] > 0
    )
    with pytest.raises(ProtocolError):
        evaluate_test(exp, "HTTP", mv)
    again = evaluate_test(exp, "HTTP", mv, rerun_reason="checking determinism")
    assert again.test_previously_seen and again.metrics["tasks"]["T1_SUSPICIOUS"]["methods"] == t1["methods"]
    assert EvaluationRun.objects.filter(experiment=exp, split="test").count() == 2


@pytest.mark.django_db
def test_labels_never_reach_feature_values(small_experiment):
    exp = small_experiment["experiment"]
    for w in FeatureWindow.objects.filter(namespace__startswith=f"ds:{exp.dataset.dataset_id}/")[:500]:
        blob = json.dumps(w.features)
        for word in ("SUSPICIOUS", "BENIGN", "scenario", "cap0", "label"):
            assert word not in blob


@pytest.mark.django_db
def test_replay_with_active_model_reproduces_experiment_scores(small_experiment):
    """Save/load/activate, replay a test capture into a replay namespace through the live
    detection path, and compare its scores with direct scoring of the experiment windows."""
    from pathlib import Path

    from ai_threat_detection.alerts.detection import ml_decisions, run_detection
    from ai_threat_detection.experiments.datasets import _dataset_source, dataset_dir
    from ai_threat_detection.features.spec import WindowConfig
    from ai_threat_detection.registry import service as reg
    from ai_threat_detection.registry.models import MLDecision
    from ai_threat_detection.sources.follow import replay

    mv = small_experiment["models"]["HTTP"]
    reg.activate(mv.model_id, "test", "activate for replay consistency")
    ds = small_experiment["dataset"]
    cap = ds.captures.order_by("-start").first()
    src = _dataset_source(ds, "HTTP")
    ns = "replay:consistency"
    replay(
        src,
        cap.files["HTTP"]["rel"],
        ns,
        on_watermark=lambda c: run_detection(ns, "HTTP", watermark=c),
        chunk_size=500,
    )
    run_detection(ns, "HTTP", finalize=True)
    cfg = WindowConfig.from_dict(mv.window_config)
    exp_windows = {
        (w.entity_key, w.window_start): w
        for w in FeatureWindow.objects.filter(
            namespace=cap.namespace, domain="HTTP", cfg_hash=cfg.config_hash()
        )
    }
    det = reg.get_active_detector("HTTP")
    replay_dec = {
        (d.window.entity_key, d.window.window_start): d
        for d in MLDecision.objects.filter(window__namespace=ns).select_related("window")
    }
    common = sorted(set(exp_windows) & set(replay_dec))
    assert len(common) > 0.9 * len(
        exp_windows
    )  # late events in replay may drop a few windows; they are flagged
    direct = ml_decisions([exp_windows[k] for k in common], det, cfg)
    diffs = [
        abs((d.get("score") or 0) - (replay_dec[k].score or 0))
        for k, d in zip(common, direct, strict=True)
        if d["status"] == "SCORED" and exp_windows[k].features == replay_dec[k].window.features
    ]
    assert diffs and max(diffs) < 1e-12
    assert np.isfinite(diffs).all()
    assert Path(dataset_dir(ds.dataset_id)).exists()
