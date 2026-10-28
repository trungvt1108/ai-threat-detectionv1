import copy
import os
import pickle
from pathlib import Path

import numpy as np
import pytest

from ai_threat_detection.features.spec import AUTH_V1, COMPUTED_FEATURES, HTTP_V1, WindowConfig
from ai_threat_detection.ml import detector as det
from ai_threat_detection.registry import service as reg
from ai_threat_detection.registry.models import ModelVersion


class W:
    def __init__(self, features, coverage=None, event_count=5, **meta):
        self.features = features
        self.coverage = coverage or {
            "status": 1.0,
            "method": 1.0,
            "bytes": 1.0,
            "duration": 1.0,
            "outcome": 1.0,
        }
        self.event_count = event_count
        for k, v in meta.items():
            setattr(self, k, v)


def http_feats(rng, scale=1.0):
    return {
        "requests": int(rng.integers(5, 30) * scale),
        "ratio_4xx": float(rng.uniform(0, 0.05)),
        "ratio_404": float(rng.uniform(0, 0.03)),
        "ratio_5xx": 0.0,
        "distinct_paths": int(rng.integers(2, 8)),
        "distinct_path_ratio": float(rng.uniform(0.2, 0.6)),
        "method_post_ratio": float(rng.uniform(0, 0.2)),
        "method_other_ratio": 0.0,
        "bytes_median": float(rng.uniform(1000, 9000)),
        "latency_median_ms": float(rng.uniform(20, 50)),
        "latency_p95_ms": float(rng.uniform(50, 120)),
    }


def test_feature_sets_are_explicit_subsets_of_computed():
    for fs in (AUTH_V1, HTTP_V1):
        assert set(fs.features) <= set(COMPUTED_FEATURES[fs.domain])
        assert set(fs.transforms) == set(fs.features)
        for banned in ("label", "scenario", "capture_id", "entity_key", "source", "file", "seed"):
            assert not any(banned in f for f in fs.features)


def test_metadata_does_not_change_matrix_or_score():
    rng = np.random.default_rng(0)
    train = [W(http_feats(rng)) for _ in range(200)]
    model, _ = det.fit_iforest(
        det.build_matrix(HTTP_V1, train, WindowConfig()).X, det.HYPERPARAM_GRID[0], 1, 1
    )
    feats = http_feats(rng)
    a = W(feats, label="SUSPICIOUS_PATTERN", capture_id="cap01", scenario="x", entity_key="ip_1")
    b = W(copy.deepcopy(feats), label="BENIGN", capture_id="zzz", scenario="y", entity_key="ip_2")
    ma, mb = det.build_matrix(HTTP_V1, [a], WindowConfig()), det.build_matrix(HTTP_V1, [b], WindowConfig())
    assert np.array_equal(ma.X, mb.X)
    assert det.anomaly_scores(model, ma.X)[0] == det.anomaly_scores(model, mb.X)[0]


def test_score_direction_extreme_is_more_anomalous():
    rng = np.random.default_rng(1)
    train = [W(http_feats(rng)) for _ in range(300)]
    model, _ = det.fit_iforest(
        det.build_matrix(HTTP_V1, train, WindowConfig()).X, det.HYPERPARAM_GRID[0], 1, 1
    )
    normal = W(http_feats(rng))
    extreme = W(
        {**http_feats(rng), "requests": 5000, "ratio_404": 0.95, "ratio_4xx": 0.97, "distinct_paths": 400}
    )
    s = det.anomaly_scores(model, det.build_matrix(HTTP_V1, [normal, extreme], WindowConfig()).X)
    assert s[1] > s[0]
    assert 0 < s[0] <= 1 and 0 < s[1] <= 1
    # matches sklearn's raw API sign convention: score_samples lower = more abnormal
    raw = model.score_samples(det.build_matrix(HTTP_V1, [normal, extreme], WindowConfig()).X)
    assert raw[1] < raw[0]


def test_missing_coverage_abstains_instead_of_low_risk():
    rng = np.random.default_rng(2)
    w = W(http_feats(rng), coverage={"status": 1.0, "method": 1.0, "bytes": 0.0, "duration": 0.0})
    w2 = W({**http_feats(rng), "latency_p95_ms": None})
    m = det.build_matrix(HTTP_V1, [w, w2, W(http_feats(rng), event_count=0)], WindowConfig())
    assert m.X.shape == (0, len(HTTP_V1.features))
    assert (
        m.abstain[0].startswith("insufficient_coverage") and m.abstain[1] == "missing_feature:latency_p95_ms"
    )
    assert m.abstain[2] == "below_min_events"


def test_threshold_selection_rules():
    scores = np.array([0.9, 0.8, 0.7, 0.6, 0.5, 0.5])
    y = np.array([1, 1, 0, 0, 0, 0])
    t, info = det.select_threshold(scores, y)
    assert t == 0.8 and info["criterion"] == "max_f1_validation"
    t2, info2 = det.select_threshold(scores, np.zeros(6, dtype=int))
    assert info2["criterion"].startswith("validation_quantile")
    with pytest.raises(ValueError):
        det.select_threshold(np.array([]), None)


def test_baseline_stats_from_train_only_unaffected_by_test_extremes():
    rng = np.random.default_rng(3)
    train = [http_feats(rng) for _ in range(100)]
    base = det.baseline_stats(HTTP_V1, train)
    snapshot = copy.deepcopy(base)
    test_extremes = [{**http_feats(rng), "requests": 10**6} for _ in range(10)]
    det.deviations(HTTP_V1, test_extremes[0], base)  # using baseline on test must not change it
    assert base == snapshot
    assert base["requests"]["q99"] < 10**5
    p = det.psi(
        base["requests"]["bin_edges"], base["requests"]["bin_props"], [t["requests"] for t in test_extremes]
    )
    assert p > 1.0


def test_percentile_is_reference_relative():
    ref = det.reference_quantiles(np.linspace(0.3, 0.6, 1000))
    assert det.score_percentile(0.29, ref) == -1 or det.score_percentile(0.29, ref) <= 0
    assert det.score_percentile(0.61, ref) == 100


@pytest.mark.django_db
def test_untrained_domain_produces_no_fake_score():
    from ai_threat_detection.alerts.detection import ml_decisions

    d = reg.get_active_detector("AUTH")
    assert d.status == "UNTRAINED" and not d.usable
    out = ml_decisions([W({}), W({})], d, WindowConfig())
    assert all(o["status"] == "UNTRAINED" and "score" not in o for o in out)


def _register(domain="HTTP"):
    rng = np.random.default_rng(4)
    train = [W(http_feats(rng)) for _ in range(100)]
    model, _ = det.fit_iforest(
        det.build_matrix(HTTP_V1, train, WindowConfig()).X, det.HYPERPARAM_GRID[0], 1, 1
    )
    mv = reg.register_candidate(
        model,
        domain=domain,
        feature_set="http_v1",
        fields=dict(
            window_config=WindowConfig().to_dict(),
            cfg_hash=WindowConfig().config_hash(),
            hyperparameters={},
            random_state=1,
            threshold=0.6,
            score_transform=det.SCORE_TRANSFORM,
            n_train=100,
        ),
    )
    return mv, model


@pytest.mark.django_db
def test_registry_save_load_roundtrip_and_integrity_checks():
    mv, model = _register()
    loaded = reg.verify_and_load(mv)
    X = np.random.default_rng(5).normal(size=(10, len(HTTP_V1.features)))
    assert np.array_equal(loaded.score_samples(X), model.score_samples(X))
    path = reg.models_root() / mv.artifact_rel
    data = path.read_bytes()
    path.write_bytes(data[:-10] + b"0123456789")
    with pytest.raises(reg.ModelLoadError) as e:
        reg.verify_and_load(mv)
    assert e.value.status == "FAILED" and "hash" in e.value.reason
    mv.artifact_sha256 = reg._sha256_file(
        path
    )  # attacker also updates the DB hash but cannot re-sign without the key
    with pytest.raises(reg.ModelLoadError) as e:
        reg.verify_and_load(mv)
    assert "signature" in e.value.reason
    path.write_bytes(data)


@pytest.mark.django_db
def test_registry_rejects_path_escape_unknown_types_and_pickles():
    mv, _ = _register()
    mv.artifact_rel = "../../keys/pseudonym.key"
    with pytest.raises(reg.ModelLoadError):
        reg.verify_and_load(mv)
    mv2, _ = _register()
    p = reg.models_root() / mv2.artifact_rel
    p.write_bytes(pickle.dumps({"not": "a model"}))  # a pickle disguised as .skops is never unpickled
    with pytest.raises(reg.ModelLoadError):
        reg.verify_and_load(mv2)


@pytest.mark.django_db
def test_dependency_and_schema_mismatch_is_incompatible():
    mv, _ = _register()
    mv.dependencies = {**mv.dependencies, "scikit-learn": "0.24.2"}
    with pytest.raises(reg.ModelLoadError) as e:
        reg.verify_and_load(mv)
    assert e.value.status == "INCOMPATIBLE"
    mv.dependencies = reg.dependency_versions()
    mv.feature_order = list(reversed(mv.feature_order))
    with pytest.raises(reg.ModelLoadError) as e:
        reg.verify_and_load(mv)
    assert e.value.status == "INCOMPATIBLE"


@pytest.mark.django_db
def test_activation_requires_validation_then_rollback_and_audit():
    from ai_threat_detection.core.models import AuditLog
    from ai_threat_detection.registry.models import ActivationHistory, ActiveModel

    a, _ = _register()
    with pytest.raises(ValueError):
        reg.activate(a.model_id, "tester", "first activation")
    ModelVersion.objects.filter(pk=a.pk).update(validation_metrics={"tasks": {}})
    reg.activate(a.model_id, "tester", "first activation")
    b, _ = _register()
    ModelVersion.objects.filter(pk=b.pk).update(validation_metrics={"tasks": {}})
    reg.activate(b.model_id, "tester", "second activation")
    assert ActiveModel.objects.get(domain="HTTP").model_id == b.pk
    assert ModelVersion.objects.get(pk=a.pk).status == "RETIRED"
    reg.rollback("HTTP", "tester", "regression found")
    assert ActiveModel.objects.get(domain="HTTP").model_id == a.pk
    assert ActivationHistory.objects.filter(action="ROLLBACK").count() == 1
    assert AuditLog.objects.filter(action__startswith="model.").count() >= 3
    with pytest.raises(ValueError):
        reg.activate(b.model_id, "tester", "")
    reg.deactivate("HTTP", "tester", "fallback to rules")
    assert reg.get_active_detector("HTTP").status == "UNTRAINED"


@pytest.mark.django_db
def test_failed_active_model_falls_back_without_score(make_source):
    from ai_threat_detection.alerts.detection import ml_decisions

    mv, _ = _register()
    ModelVersion.objects.filter(pk=mv.pk).update(validation_metrics={"tasks": {}})
    reg.activate(mv.model_id, "t", "activate for test")
    reg.clear_cache()
    os.remove(reg.models_root() / mv.artifact_rel)
    d = reg.get_active_detector("HTTP")
    assert d.status == "FAILED" and not d.usable
    assert all(o["status"] == "FAILED" and "score" not in o for o in ml_decisions([W({})], d, WindowConfig()))


def test_no_ui_route_accepts_model_files():
    from django.urls import get_resolver

    patterns = [str(p.pattern) for p in get_resolver().url_patterns]
    assert not any("upload" in p for p in patterns)
    src = Path(reg.__file__).read_text(encoding="utf-8")
    assert "pickle.load" not in src and "joblib.load" not in src
