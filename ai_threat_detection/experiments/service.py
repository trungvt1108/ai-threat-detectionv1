"""Experiment protocol implementation (see docs/EVALUATION_PROTOCOL.md).

1. ``create_experiment``: capture groups are assigned chronologically to
   train / validation / test BEFORE any fitting; a purge gap >= window size +
   lateness is enforced between splits; windows are built per capture namespace
   (so no window spans two captures); labels resolved from sidecars; split
   manifest + diagnostics written.
2. ``train_detector``: IsolationForest fit on train BENIGN windows only
   (novelty setting); hyperparameters from a fixed small grid chosen by
   validation AP; threshold chosen on validation (max F1, T1 task). Baseline
   stats / reference score quantiles come from train only.
3. ``evaluate_test``: frozen model + threshold + current rule versions on the
   test split. Re-running the test evaluation requires a reason and marks the
   run ``test_previously_seen``.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import numpy as np
from django.utils import timezone

from ai_threat_detection.alerts.policy import COOLDOWN
from ai_threat_detection.conf import get_config
from ai_threat_detection.core.audit import audit
from ai_threat_detection.features.builder import build_windows
from ai_threat_detection.features.compute import transform_row
from ai_threat_detection.features.models import FeatureWindow
from ai_threat_detection.features.spec import DEFAULT_FEATURE_SET, ML_DOMAINS, WindowConfig, get_feature_set
from ai_threat_detection.ml import detector as det
from ai_threat_detection.normalization.pseudonym import Pseudonymizer
from ai_threat_detection.registry.models import ModelVersion
from ai_threat_detection.registry.service import register_candidate, verify_and_load
from ai_threat_detection.rules.engine import evaluate_all
from ai_threat_detection.rules.service import current_rules, rule_versions_snapshot

from .datasets import load_intervals
from .metrics import TASKS, evaluate_units, window_label
from .models import Capture, Dataset, EvaluationRun, Experiment

PROTOCOL_VERSION = "atd-eval-protocol-v1"
SPLITS = ("train", "validation", "test")


class ProtocolError(ValueError):
    pass


def _exp_dir(exp_id: str) -> Path:
    d = get_config().experiments_dir / exp_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def assign_splits(
    captures: list[Capture], counts: tuple[int, int, int] | None, proportions=(0.5, 0.2, 0.3)
) -> dict[str, str]:
    """Chronological assignment by scenario group (a group never spans two splits)."""
    groups: dict[str, list[Capture]] = {}
    for c in captures:
        groups.setdefault(c.scenario_group, []).append(c)
    ordered = sorted(groups.items(), key=lambda kv: min(c.start for c in kv[1]))
    n = len(ordered)
    if n < 3:
        raise ProtocolError("need at least 3 capture groups for train/validation/test")
    if counts is None:
        n_train = max(1, int(round(n * proportions[0])))
        n_val = max(1, int(round(n * proportions[1])))
        n_test = n - n_train - n_val
        if n_test < 1:
            n_train -= 1
            n_test = 1
        counts = (n_train, n_val, n_test)
    if sum(counts) != n or min(counts) < 1:
        raise ProtocolError(f"split counts {counts} do not cover {n} groups")
    out = {}
    names = ["train"] * counts[0] + ["validation"] * counts[1] + ["test"] * counts[2]
    for (_group, caps), split in zip(ordered, names, strict=True):
        for c in caps:
            out[c.capture_id] = split
    return out


def check_temporal_gaps(
    captures: list[Capture], assignment: dict[str, str], gap: timedelta
) -> dict[str, Any]:
    ranges = {}
    for s in SPLITS:
        cs = [c for c in captures if assignment[c.capture_id] == s]
        ranges[s] = (min(c.start for c in cs), max(c.end for c in cs))
    problems = []
    for a, b in (("train", "validation"), ("validation", "test")):
        if ranges[a][1] + gap > ranges[b][0]:
            problems.append(f"{a} end + gap overlaps {b} start")
    if problems:
        raise ProtocolError("; ".join(problems))
    return {s: {"start": r[0].isoformat(), "end": r[1].isoformat()} for s, r in ranges.items()}


def create_experiment(
    dataset: Dataset,
    exp_id: str,
    name: str,
    cfg: WindowConfig,
    counts: tuple[int, int, int] | None = None,
    random_state: int = 20260101,
    feature_sets: dict[str, str] | None = None,
    actor=None,
    ctx=None,
) -> Experiment:
    if dataset.status != "IMPORTED":
        raise ProtocolError("dataset must be imported first")
    if Experiment.objects.filter(exp_id=exp_id).exists():
        raise ProtocolError("experiment id exists; experiments are immutable, choose a new id")
    fsets = feature_sets or dict(DEFAULT_FEATURE_SET)
    for dom, fs in fsets.items():
        if get_feature_set(fs).domain != dom:
            raise ProtocolError("feature set/domain mismatch")
    captures = list(dataset.captures.order_by("start"))
    assignment = assign_splits(captures, counts)
    gap = timedelta(seconds=cfg.size_s + cfg.allowed_lateness_s)
    ranges = check_temporal_gaps(captures, assignment, gap)
    key_id = Pseudonymizer.from_local_key().key_id
    if dataset.pseudonym_key_id and dataset.pseudonym_key_id != key_id:
        raise ProtocolError("pseudonymization key changed since dataset import; labels would not match")

    windows_by_split: dict[str, dict[str, list[dict[str, Any]]]] = {
        s: {d: [] for d in ML_DOMAINS} for s in SPLITS
    }
    for cap in captures:
        intervals, bg = load_intervals(cap)
        for dom in ML_DOMAINS:
            build_windows(cap.namespace, dom, cfg, finalize=True, ctx=ctx, track=False)
            qs = FeatureWindow.objects.filter(namespace=cap.namespace, domain=dom, cfg_hash=cfg.config_hash())
            for w in qs.order_by("window_start", "entity_key"):
                label, scenario, instance = window_label(
                    dom, w.entity_key, w.window_start, w.window_end, intervals, bg
                )
                windows_by_split[assignment[cap.capture_id]][dom].append(
                    {
                        "id": w.pk,
                        "capture": cap.capture_id,
                        "label": label,
                        "scenario": scenario,
                        "instance": instance,
                    }
                )

    diagnostics = _diagnostics(windows_by_split, fsets, cfg)
    manifest = {
        "protocol_version": PROTOCOL_VERSION,
        "experiment_id": exp_id,
        "dataset": {
            "id": dataset.dataset_id,
            "manifest_sha256": dataset.manifest_sha256,
            "provenance": dataset.provenance,
            "privacy_class": dataset.privacy_class,
        },
        "pseudonym_key_id": key_id,
        "window_config": cfg.to_dict(),
        "cfg_hash": cfg.config_hash(),
        "feature_sets": {d: get_feature_set(f).to_dict() for d, f in fsets.items()},
        "split_method": "chronological by scenario group; groups never span splits; purge gap >= window size + lateness",
        "purge_gap_seconds": gap.total_seconds(),
        "assignment": assignment,
        "split_time_ranges": ranges,
        "counts": {s: {d: _label_counts(windows_by_split[s][d]) for d in ML_DOMAINS} for s in SPLITS},
        "window_id_hashes": {
            s: {d: _sha(sorted(x["id"] for x in windows_by_split[s][d])) for d in ML_DOMAINS} for s in SPLITS
        },
        "diagnostics": diagnostics,
        "created_at": timezone.now().isoformat(),
    }
    d = _exp_dir(exp_id)
    (d / "split_windows.json").write_text(json.dumps(windows_by_split), encoding="utf-8")
    mpath = d / "split_manifest.json"
    mpath.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    exp = Experiment.objects.create(
        exp_id=exp_id,
        dataset=dataset,
        name=name,
        protocol_version=PROTOCOL_VERSION,
        window_config=cfg.to_dict(),
        cfg_hash=cfg.config_hash(),
        feature_sets=fsets,
        random_state=random_state,
        split_manifest_rel=f"{exp_id}/split_manifest.json",
        split_manifest_sha256=hashlib.sha256(mpath.read_bytes()).hexdigest(),
        status="SPLIT_READY",
        created_by=actor if getattr(actor, "is_authenticated", False) else None,
    )
    audit(actor, "experiment.create", "experiment", exp_id, "", dataset=dataset.dataset_id, cfg=cfg.to_dict())
    return exp


def _label_counts(items: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for x in items:
        out[x["label"]] = out.get(x["label"], 0) + 1
    return out


def _diagnostics(wbs: dict, fsets: dict[str, str], cfg: WindowConfig) -> dict[str, Any]:
    """Leakage checks: window/capture disjointness, entity overlap and exact
    duplicate model vectors across splits (expected for tiny windows; reported)."""
    out: dict[str, Any] = {}
    for dom in ML_DOMAINS:
        fs = get_feature_set(fsets[dom])
        ids = {s: {x["id"] for x in wbs[s][dom]} for s in SPLITS}
        caps = {s: {x["capture"] for x in wbs[s][dom]} for s in SPLITS}
        pk_to_split = {pk: s for s in SPLITS for pk in ids[s]}
        windows = FeatureWindow.objects.filter(pk__in=list(pk_to_split)).only(
            "pk", "entity_key", "features", "coverage", "event_count"
        )
        vecs: dict[str, set] = {s: set() for s in SPLITS}
        ents: dict[str, set] = {s: set() for s in SPLITS}
        for w in windows:
            s = pk_to_split[w.pk]
            ents[s].add(w.entity_key)
            try:
                vecs[s].add(tuple(round(v, 9) for v in transform_row(fs, w.features)))
            except (TypeError, KeyError):
                pass
        out[dom] = {
            "window_overlap_train_val": len(ids["train"] & ids["validation"]),
            "window_overlap_train_test": len(ids["train"] & ids["test"]),
            "window_overlap_val_test": len(ids["validation"] & ids["test"]),
            "capture_overlap": len(
                (caps["train"] & caps["test"])
                | (caps["train"] & caps["validation"])
                | (caps["validation"] & caps["test"])
            ),
            "entity_overlap_train_test": len(ents["train"] & ents["test"]),
            "distinct_vectors": {s: len(vecs[s]) for s in SPLITS},
            "test_vectors_also_in_train": len(vecs["test"] & vecs["train"]),
            "note": "identities are not model inputs; shared normal entities across splits are expected. "
            "Identical low-count feature vectors across splits are expected for small windows.",
        }
    return out


def _load_split(exp: Experiment) -> dict:
    p = get_config().experiments_dir / exp.exp_id / "split_windows.json"
    mp = get_config().experiments_dir / exp.split_manifest_rel
    if hashlib.sha256(mp.read_bytes()).hexdigest() != exp.split_manifest_sha256:
        raise ProtocolError("split manifest changed on disk")
    return json.loads(p.read_text(encoding="utf-8"))


def _windows(items: list[dict]) -> tuple[list[FeatureWindow], list[dict]]:
    by_pk = {w.pk: w for w in FeatureWindow.objects.filter(pk__in=[x["id"] for x in items])}
    ws, meta = [], []
    for x in items:
        w = by_pk.get(x["id"])
        if w is not None:
            ws.append(w)
            meta.append(x)
    return ws, meta


def _observed_hours(exp: Experiment, split: str, wbs: dict) -> float:
    caps = {x["capture"] for d in ML_DOMAINS for x in wbs[split][d]}
    total = 0.0
    for c in Capture.objects.filter(dataset=exp.dataset, capture_id__in=caps):
        total += (c.end - c.start).total_seconds() / 3600.0
    return total


def _units(
    domain: str,
    windows: list[FeatureWindow],
    meta: list[dict],
    fs,
    cfg: WindowConfig,
    model,
    threshold: float,
):
    rules = current_rules(domain)
    t0 = time.perf_counter()
    rule_hits = []
    for w in windows:
        res = [r for r in evaluate_all(rules, domain, w.features) if r.status == "TRIGGERED"]
        rule_hits.append((any(r.category == "threat" for r in res), bool(res)))
    t_rules = time.perf_counter() - t0
    t1 = time.perf_counter()
    mat = det.build_matrix(fs, windows, cfg)
    scores = (
        det.anomaly_scores(model, mat.X, get_config().max_cpu_threads) if model is not None else np.zeros(0)
    )
    t_ml = time.perf_counter() - t1
    score_by_i = {i: float(scores[j]) for j, i in enumerate(mat.eligible_idx)}
    units = []
    for i, (w, m) in enumerate(zip(windows, meta, strict=True)):
        s = score_by_i.get(i)
        units.append(
            {
                "label": m["label"],
                "scenario": m.get("scenario"),
                "instance": m.get("instance"),
                "entity": w.entity_key,
                "start": w.window_start,
                "end": w.window_end,
                "rule_hit_threat": rule_hits[i][0],
                "rule_hit_any": rule_hits[i][1],
                "ml_status": "SCORED" if s is not None else "INSUFFICIENT_DATA",
                "ml_score": s,
                "ml_hit": (s is not None and s >= threshold),
            }
        )
    timing = {
        "windows": len(windows),
        "ml_eligible": len(mat.eligible_idx),
        "ml_batch_seconds": round(t_ml, 6),
        "ml_windows_per_second": round(len(windows) / t_ml, 1) if t_ml > 0 else None,
        "rules_batch_seconds": round(t_rules, 6),
        "note": "measured wall-clock on this machine for one batch over the split (matrix build + score)",
    }
    return units, mat, scores, timing


def _evaluate(exp, domain, split, wbs, fs, cfg, model, threshold) -> dict[str, Any]:
    windows, meta = _windows(wbs[split][domain])
    units, _, _, timing = _units(domain, windows, meta, fs, cfg, model, threshold)
    hours = _observed_hours(exp, split, wbs)
    return {
        "split": split,
        "domain": domain,
        "threshold": threshold,
        "rule_versions": {k: v for k, v in rule_versions_snapshot().items() if k.startswith(domain[:4])},
        "tasks": {t: evaluate_units(units, t, hours, COOLDOWN) for t in TASKS},
        "timing": timing,
        "provenance": exp.dataset.provenance,
        "caveat": _caveat(exp.dataset.provenance),
    }


def _caveat(prov: str) -> str:
    if prov == "SYNTHETIC_DEMO":
        return "Synthetic data: metrics only show behavior on this generator's distributions, not real-world performance."
    if prov == "LAB_OBSERVED":
        return "Local lab observation with a project fixture and scripted driver; not production validation."
    return "Results depend on the dataset's labels and coverage; see protocol limitations."


def train_detector(
    exp: Experiment, domain: str, actor=None, train_on_unknown: bool = False, ctx=None
) -> ModelVersion:
    if domain not in ML_DOMAINS:
        raise ProtocolError(f"{domain}: no ML model in v1 (UPSTREAM_ONLY or unsupported)")
    cfg = WindowConfig.from_dict(exp.window_config)
    fs = get_feature_set(exp.feature_sets[domain])
    wbs = _load_split(exp)
    train_ok = {"BENIGN"} | ({"UNKNOWN"} if train_on_unknown else set())
    tw, tmeta = _windows(wbs["train"][domain])
    excluded = sum(1 for m in tmeta if m["label"] not in train_ok)
    train_ws = [w for w, m in zip(tw, tmeta, strict=True) if m["label"] in train_ok]
    mat_tr = det.build_matrix(fs, train_ws, cfg)
    vw, vmeta = _windows(wbs["validation"][domain])
    mat_v = det.build_matrix(fs, vw, cfg)
    y_v_all = np.asarray([1 if m["label"] in TASKS["T1_SUSPICIOUS"]["positive"] else 0 for m in vmeta])
    known_v = np.asarray([m["label"] != "UNKNOWN" for m in vmeta])
    elig = np.asarray(mat_v.eligible_idx, dtype=int)
    keep = known_v[elig] if len(elig) else np.zeros(0, dtype=bool)
    Xv = mat_v.X[keep] if len(elig) else mat_v.X
    yv = y_v_all[elig][keep] if len(elig) else np.zeros(0)
    selected_on = "validation split (T1_SUSPICIOUS labels)"
    if len(Xv) == 0 and train_on_unknown and len(elig):
        # Unlabeled operator data: no labelled validation windows exist, so the threshold falls
        # back to the pre-declared quantile rule over all eligible validation windows.
        Xv, yv = mat_v.X, np.zeros(0)
        selected_on = "validation split, unlabeled (UNKNOWN windows as reference; train_on_unknown)"
    if len(Xv) == 0:
        raise ProtocolError(
            f"{domain}: no eligible labelled validation windows "
            "(unlabeled data needs --train-on-unknown; or the validation split has too little data)"
        )
    n_jobs = get_config().max_cpu_threads
    if ctx is not None:
        ctx.heartbeat(stage="hyperparameter_selection", n_train=int(mat_tr.X.shape[0]))
    params, trials = det.choose_hyperparams(mat_tr.X, Xv, yv if len(yv) else None, exp.random_state, n_jobs)
    model, fit_s = det.fit_iforest(mat_tr.X, params, exp.random_state, n_jobs)
    train_scores = det.anomaly_scores(model, mat_tr.X, n_jobs)
    val_scores = det.anomaly_scores(model, Xv, n_jobs)
    threshold, crit = det.select_threshold(val_scores, yv if len(yv) else None)
    crit["selected_on"] = selected_on
    eligible_train = set(mat_tr.eligible_idx)
    baseline = det.baseline_stats(fs, [w.features for i, w in enumerate(train_ws) if i in eligible_train])
    train_cutoff = max((w.window_end for w in train_ws), default=None)
    mv = register_candidate(
        model,
        domain=domain,
        feature_set=fs.name,
        fields=dict(
            window_config=cfg.to_dict(),
            cfg_hash=cfg.config_hash(),
            hyperparameters={**params, "contamination": "auto", "bootstrap": False},
            hyperparameter_trials=trials,
            random_state=exp.random_state,
            pseudonym_key_id=Pseudonymizer.from_local_key().key_id,
            experiment=exp,
            split_manifest_sha256=exp.split_manifest_sha256,
            train_cutoff=train_cutoff,
            n_train=int(mat_tr.X.shape[0]),
            train_exclusions={
                "non_baseline_label_windows": excluded,
                "ml_ineligible_windows": len(mat_tr.abstain),
                "abstain_reasons": _reason_counts(mat_tr.abstain),
                "train_labels_used": sorted(train_ok),
            },
            training_seconds=round(fit_s, 4),
            threshold=float(threshold),
            threshold_criterion=crit,
            score_transform=det.SCORE_TRANSFORM,
            reference_score_quantiles=det.reference_quantiles(train_scores),
            baseline_stats=baseline,
            created_by=actor if getattr(actor, "is_authenticated", False) else None,
        ),
    )
    # Save/load consistency: reload through the registry gate and re-score validation.
    reloaded = verify_and_load(mv)
    diff = (
        float(np.max(np.abs(det.anomaly_scores(reloaded, Xv, n_jobs) - val_scores)))
        if len(val_scores)
        else 0.0
    )
    val_metrics = _evaluate(exp, domain, "validation", wbs, fs, cfg, reloaded, float(threshold))
    val_metrics["save_load_max_abs_score_diff"] = diff
    mv.validation_metrics = val_metrics
    mv.save(update_fields=["validation_metrics"])
    EvaluationRun.objects.create(
        experiment=exp,
        domain=domain,
        split="validation",
        model=mv,
        metrics=val_metrics,
        created_by=mv.created_by,
    )
    from ai_threat_detection.reports.model_card import write_model_card

    write_model_card(mv)
    exp.status = "TRAINED"
    exp.save(update_fields=["status"])
    audit(
        actor,
        "model.train",
        "model",
        mv.model_id,
        "",
        experiment=exp.exp_id,
        domain=domain,
        threshold=threshold,
    )
    return mv


def _reason_counts(abstain: dict[int, str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in abstain.values():
        out[r] = out.get(r, 0) + 1
    return out


def evaluate_test(
    exp: Experiment, domain: str, mv: ModelVersion, actor=None, rerun_reason: str = ""
) -> EvaluationRun:
    if mv.experiment_id != exp.pk or mv.domain != domain:
        raise ProtocolError("model does not belong to this experiment/domain")
    prior = EvaluationRun.objects.filter(experiment=exp, domain=domain, split="test")
    seen = prior.exists()
    if seen and len(rerun_reason.strip()) < 5:
        raise ProtocolError(
            "test split already evaluated for this experiment/domain; re-running requires --rerun-reason "
            "and the run will be marked test_previously_seen (no longer an unseen test)"
        )
    cfg = WindowConfig.from_dict(exp.window_config)
    fs = get_feature_set(mv.feature_set)
    wbs = _load_split(exp)
    model = verify_and_load(mv)
    metrics = _evaluate(exp, domain, "test", wbs, fs, cfg, model, mv.threshold)
    metrics["threshold_version"] = mv.threshold_version
    metrics["test_previously_seen"] = seen
    run = EvaluationRun.objects.create(
        experiment=exp,
        domain=domain,
        split="test",
        model=mv,
        metrics=metrics,
        run_index=prior.count() + 1,
        test_previously_seen=seen,
        rerun_reason=rerun_reason[:500],
        created_by=actor if getattr(actor, "is_authenticated", False) else None,
    )
    if not seen:
        mv.test_metrics = metrics
        mv.save(update_fields=["test_metrics"])
    exp.status = "TEST_EVALUATED"
    exp.save(update_fields=["status"])
    from ai_threat_detection.reports.model_card import write_model_card

    write_model_card(mv)
    audit(
        actor,
        "experiment.evaluate_test",
        "experiment",
        exp.exp_id,
        rerun_reason,
        domain=domain,
        model=mv.model_id,
        previously_seen=seen,
    )
    return run
