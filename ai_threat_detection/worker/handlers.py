"""Job kind -> implementation. Every handler takes (params, ctx, job) and returns a JSON-able dict."""

from __future__ import annotations

from typing import Any

from ai_threat_detection.features.spec import ML_DOMAINS, WindowConfig


def _source(name: str):
    from ai_threat_detection.sources.models import Source

    src = Source.objects.get(name=name)
    if not src.enabled:
        raise ValueError("source disabled")
    return src


def _detect_all(namespace: str, finalize: bool, ctx, domains=None) -> dict[str, Any]:
    from ai_threat_detection.alerts.detection import process_upstream_ids, run_detection

    out = {}
    for dom in domains or ML_DOMAINS:
        out[dom] = run_detection(namespace, dom, finalize=finalize, ctx=ctx)
    out["EVE"] = process_upstream_ids(namespace)
    return out


def h_import(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.alerts.health import evaluate_ingest_health
    from ai_threat_detection.sources.ingest import IngestOptions, import_source_file

    src = _source(params["source"])
    ns = params.get("namespace") or "live"
    if ns.startswith(("ds:", "replay:")):
        raise ValueError("import into experiment/replay namespaces is not allowed here")
    run = import_source_file(
        src,
        params["file"],
        IngestOptions(namespace=ns, from_start=bool(params.get("from_start"))),
        ctx=ctx,
        job_id=job.pk,
    )
    res: dict[str, Any] = {
        "ingest_run": run.pk,
        "status": run.status,
        "accepted": run.accepted,
        "duplicates": run.duplicates,
        "rejected": run.rejected,
        "skipped": run.skipped,
        "reject_reasons": run.reject_reasons,
        "late": run.late_events,
        "future": run.future_events,
        "notes": run.notes,
    }
    res["health_alerts"] = evaluate_ingest_health(run)
    if params.get("detect", True):
        res["detection"] = _detect_all(ns, bool(params.get("finalize", False)), ctx)
    return res


def h_follow(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.alerts.health import evaluate_staleness
    from ai_threat_detection.sources.follow import follow

    src = _source(params["source"])
    ns = "live"
    detect = bool(params.get("detect", True))

    def after_poll():
        if detect:
            _detect_all(ns, False, ctx)
        evaluate_staleness(src, ns)

    totals = follow(
        src,
        params["file"],
        namespace=ns,
        duration_s=float(params.get("duration_s", 60)),
        poll_s=float(params.get("poll_s", 1.0)),
        ctx=ctx,
        job_id=job.pk,
        after_poll=after_poll,
    )
    return totals


def h_replay(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.alerts.detection import run_detection
    from ai_threat_detection.sources.follow import replay

    src = _source(params["source"])
    ns = params.get("namespace") or f"replay:job{job.pk}"
    domains = {"http_json": ["HTTP"], "auth_json": ["AUTH"]}.get(src.source_type, [])
    calls = {"n": 0}

    def on_watermark(clock):
        calls["n"] += 1
        for d in domains:
            run_detection(ns, d, watermark=clock, ctx=ctx)

    run = replay(
        src,
        params["file"],
        ns,
        speed=float(params.get("speed", 0)),
        on_watermark=on_watermark,
        chunk_size=int(params.get("chunk_size", 200)),
        ctx=ctx,
        job_id=job.pk,
    )
    final = {}
    if params.get("finalize", True):
        for d in domains:
            final[d] = run_detection(ns, d, finalize=True, ctx=ctx)
    return {
        "namespace": ns,
        "accepted": run.accepted,
        "rejected": run.rejected,
        "late": run.late_events,
        "detection_calls": calls["n"],
        "final": final,
    }


def h_detect(params, ctx, job) -> dict[str, Any]:
    if params.get("dataset"):
        # Every capture namespace of an imported dataset, with all windows closed.
        from ai_threat_detection.experiments.models import Dataset

        ds = Dataset.objects.get(dataset_id=params["dataset"])
        if ds.status != "IMPORTED":
            raise ValueError("dataset must be imported first")
        return {
            cap.capture_id: _detect_all(cap.namespace, True, ctx, params.get("domains"))
            for cap in ds.captures.order_by("start")
        }
    return _detect_all(
        params.get("namespace", "live"), bool(params.get("finalize", False)), ctx, params.get("domains")
    )


def h_generate_synthetic(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.demo.synthetic import generate_dataset

    path = generate_dataset(
        params["dataset_id"], seed=int(params.get("seed", 1337)), n_captures=int(params.get("n_captures", 10))
    )
    return {"manifest": path.name, "dataset_id": params["dataset_id"]}


def h_import_dataset(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.experiments.datasets import import_dataset, register_dataset

    ds = register_dataset(params["dataset"], actor=job.created_by)
    return {"dataset": ds.dataset_id, "captures": import_dataset(ds, ctx=ctx, job_id=job.pk)}


def h_create_experiment(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.experiments.models import Dataset
    from ai_threat_detection.experiments.service import create_experiment

    ds = Dataset.objects.get(dataset_id=params["dataset"])
    cfg = WindowConfig(**params.get("window", {}))
    counts = tuple(params["counts"]) if params.get("counts") else None
    exp = create_experiment(
        ds,
        params["exp_id"],
        params.get("name", params["exp_id"]),
        cfg,
        counts=counts,
        random_state=int(params.get("random_state", 20260101)),
        feature_sets=params.get("feature_sets") or None,
        actor=job.created_by,
        ctx=ctx,
    )
    return {"experiment": exp.exp_id, "split_manifest_sha256": exp.split_manifest_sha256}


def h_train(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.experiments.models import Experiment
    from ai_threat_detection.experiments.service import train_detector

    exp = Experiment.objects.get(exp_id=params["experiment"])
    mv = train_detector(
        exp,
        params["domain"],
        actor=job.created_by,
        train_on_unknown=bool(params.get("train_on_unknown")),
        ctx=ctx,
    )
    t1 = mv.validation_metrics["tasks"]["T1_SUSPICIOUS"]["methods"]
    return {
        "model_id": mv.model_id,
        "threshold": mv.threshold,
        "n_train": mv.n_train,
        "training_seconds": mv.training_seconds,
        "validation_f1": {k: v["f1"] for k, v in t1.items()},
        "save_load_max_abs_score_diff": mv.validation_metrics.get("save_load_max_abs_score_diff"),
    }


def h_evaluate(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.experiments.models import Experiment
    from ai_threat_detection.experiments.service import evaluate_test
    from ai_threat_detection.registry.models import ModelVersion

    exp = Experiment.objects.get(exp_id=params["experiment"])
    mv = ModelVersion.objects.get(model_id=params["model_id"])
    run = evaluate_test(
        exp, params["domain"], mv, actor=job.created_by, rerun_reason=params.get("rerun_reason", "")
    )
    t1 = run.metrics["tasks"]["T1_SUSPICIOUS"]["methods"]
    return {
        "evaluation_run": run.pk,
        "test_previously_seen": run.test_previously_seen,
        "test_f1": {k: v["f1"] for k, v in t1.items()},
    }


def h_lab_capture(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.lab.capture import run_lab_capture

    return run_lab_capture(params["dataset_id"], profile=params.get("profile", "default"), ctx=ctx)


def h_report(params, ctx, job) -> dict[str, Any]:
    from ai_threat_detection.reports.export import export_report

    return export_report(params, actor=job.created_by)


HANDLERS = {
    "import": h_import,
    "follow": h_follow,
    "replay": h_replay,
    "detect": h_detect,
    "generate_synthetic": h_generate_synthetic,
    "import_dataset": h_import_dataset,
    "create_experiment": h_create_experiment,
    "train": h_train,
    "evaluate": h_evaluate,
    "lab_capture": h_lab_capture,
    "report": h_report,
}
