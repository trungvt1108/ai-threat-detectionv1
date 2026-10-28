"""Report export (Markdown / HTML / JSON) from real DB records.

Private reports go to ``<data_dir>/reports``. ``public_draft=True`` produces a
reduced variant under ``<data_dir>/public_drafts`` (entity pseudonyms and source
names replaced by per-report aliases, no event samples, no paths) that still
needs human review and ``publish_check`` before anything is shared.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections import Counter
from datetime import timedelta
from typing import Any

from django.template.loader import render_to_string
from django.utils import timezone

from ai_threat_detection.alerts.models import Alert
from ai_threat_detection.conf import get_config
from ai_threat_detection.core.audit import audit
from ai_threat_detection.experiments.models import EvaluationRun, Experiment
from ai_threat_detection.registry.models import ActiveModel, ModelVersion
from ai_threat_detection.rules.service import rule_versions_snapshot
from ai_threat_detection.sources.models import IngestRun, Source

from .model_card import fmt
from .models import Report

MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>])")


def md_escape(s: Any) -> str:
    return MD_SPECIAL.sub(r"\\\1", str(s))


class Aliaser:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.map: dict[str, str] = {}

    def __call__(self, kind: str, value: str | None) -> str:
        if not value:
            return ""
        if not self.enabled:
            return value
        key = f"{kind}:{value}"
        if key not in self.map:
            self.map[key] = f"{kind}-{sum(1 for k in self.map if k.startswith(kind + ':')) + 1}"
        return self.map[key]


def _limitations(prov: str | None) -> list[str]:
    out = [
        "Anomaly score là điểm xếp hạng, không phải xác suất tấn công; bất thường không chứng minh có tấn công.",
        "Alert là nhóm theo entity/cooldown; số alert không phải số vụ tấn công.",
        "Rule thresholds là điểm khởi đầu theo mô tả rule, không được tinh chỉnh theo nhãn test.",
        "ML abstain (INSUFFICIENT_DATA) khi thiếu coverage; các cửa sổ đó được tính là 'không có ML alert'.",
    ]
    if prov == "SYNTHETIC_DEMO":
        out.append(
            "Dữ liệu tổng hợp: metrics chỉ phản ánh hành vi trên generator này, không phải hiệu năng thực tế."
        )
    if prov == "LAB_OBSERVED":
        out.append(
            "Quan sát lab local với fixture và driver kịch bản; không phải production validation. Cửa sổ ngắn (lab)."
        )
    return out


def experiment_data(exp: Experiment, alias: Aliaser) -> dict[str, Any]:
    manifest = json.loads((get_config().experiments_dir / exp.split_manifest_rel).read_text(encoding="utf-8"))
    models = []
    for mv in ModelVersion.objects.filter(experiment=exp).order_by("domain", "-created_at"):
        tests = list(
            EvaluationRun.objects.filter(experiment=exp, model=mv, split="test").order_by("created_at")
        )
        models.append(
            {
                "model_id": mv.model_id,
                "domain": mv.domain,
                "status": mv.status,
                "feature_set": mv.feature_set,
                "feature_schema_version": mv.feature_schema_version,
                "feature_order": mv.feature_order,
                "hyperparameters": mv.hyperparameters,
                "threshold": mv.threshold,
                "threshold_version": mv.threshold_version,
                "threshold_criterion": mv.threshold_criterion,
                "score_transform": mv.score_transform,
                "n_train": mv.n_train,
                "training_seconds": mv.training_seconds,
                "train_exclusions": mv.train_exclusions,
                "artifact_sha256": mv.artifact_sha256,
                "dependencies": mv.dependencies,
                "validation": mv.validation_metrics,
                "test_runs": [
                    {
                        "run_index": t.run_index,
                        "test_previously_seen": t.test_previously_seen,
                        "rerun_reason": t.rerun_reason,
                        "metrics": t.metrics,
                    }
                    for t in tests
                ],
            }
        )
    ds = exp.dataset
    return {
        "kind": "experiment",
        "experiment": {
            "id": exp.exp_id,
            "name": exp.name,
            "protocol_version": exp.protocol_version,
            "status": exp.status,
            "split_manifest_sha256": exp.split_manifest_sha256,
        },
        "dataset": {
            "id": ds.dataset_id,
            "provenance": ds.provenance,
            "privacy_class": ds.privacy_class,
            "license": ds.license,
            "usage_constraints": ds.usage_constraints,
            "manifest_sha256": ds.manifest_sha256,
            "label_definition": ds.label_definition,
        },
        "window_config": exp.window_config,
        "feature_sets": manifest["feature_sets"],
        "split": {
            k: manifest[k]
            for k in (
                "split_method",
                "purge_gap_seconds",
                "assignment",
                "split_time_ranges",
                "counts",
                "diagnostics",
            )
        },
        "rules": rule_versions_snapshot(),
        "models": models,
        "comparison": _comparison(models),
        "limitations": _limitations(ds.provenance),
        "reproduce": [
            f"python manage.py import_dataset --dataset {ds.dataset_id}",
            f"python manage.py create_experiment --dataset {ds.dataset_id} --exp-id {exp.exp_id} "
            f"--window-size {exp.window_config['size_s']} --stride {exp.window_config['stride_s']} "
            f"--lateness {exp.window_config['allowed_lateness_s']}",
            f"python manage.py train_detector --experiment {exp.exp_id} --domain AUTH",
            f"python manage.py train_detector --experiment {exp.exp_id} --domain HTTP",
            f"python manage.py evaluate_detector --experiment {exp.exp_id} --domain <AUTH|HTTP> --model <model_id>",
            f"python manage.py export_report --experiment {exp.exp_id}",
        ],
    }


def _comparison(models: list[dict]) -> list[str]:
    lines = []
    for m in models:
        runs = m["test_runs"]
        if not runs:
            lines.append(f"{m['domain']} {m['model_id']}: chưa có đánh giá test.")
            continue
        t = runs[0]["metrics"]["tasks"]["T1_SUSPICIOUS"]["methods"]
        f1s = {k: v["f1"] for k, v in t.items()}
        defined = {k: v for k, v in f1s.items() if v is not None}
        if not defined:
            lines.append(f"{m['domain']}: F1 không xác định trên test (thiếu positive/negative).")
            continue
        best = max(defined, key=defined.get)
        lines.append(
            f"{m['domain']} (test, T1): F1 rules_only={fmt(f1s['rules_only'])}, ml_only={fmt(f1s['ml_only'])}, "
            f"hybrid_or={fmt(f1s['hybrid_or'])} → cao nhất: {best}."
            + (
                " Rule baseline không thua ML trên tập này."
                if defined.get("rules_only", -1) >= defined.get("ml_only", -1)
                else ""
            )
        )
    return lines


def alerts_data(namespace: str, days: int, alias: Aliaser, public: bool) -> dict[str, Any]:
    since = timezone.now() - timedelta(days=days)
    qs = Alert.objects.filter(namespace=namespace, created_at__gte=since)
    total = qs.count()
    sources = []
    for s in Source.objects.all():
        last = IngestRun.objects.filter(source=s, namespace=namespace).first()
        h = getattr(s, "health", None)
        sources.append(
            {
                "source": alias("source", s.name),
                "type": s.source_type,
                "provenance": s.provenance,
                "health": h.status if h else "NEVER_RUN",
                "last_run": {
                    "status": last.status,
                    "accepted": last.accepted,
                    "rejected": last.rejected,
                    "reject_reasons": last.reject_reasons,
                }
                if last
                else None,
            }
        )
    ml = {}
    for dom in ("AUTH", "HTTP"):
        am = ActiveModel.objects.filter(domain=dom).select_related("model").first()
        ml[dom] = {
            "active_model": am.model.model_id if am else None,
            "status": "ACTIVE" if am else "UNTRAINED (rules-only)",
        }
    top = []
    for a in qs.order_by("-window_end")[:50]:
        item = {
            "id": a.pk,
            "domain": a.domain,
            "entity": alias("entity", a.entity_key),
            "window_start": a.window_start.isoformat(),
            "window_end": a.window_end.isoformat(),
            "detection_source": a.detection_source,
            "severity": a.severity,
            "title": a.title if not public else re.sub(r"(ip|user|host)_[0-9a-f]{16}", "[entity]", a.title),
            "decisions": a.decision_count,
            "workflow": a.workflow_status,
            "assessment": a.assessment,
            "suppressed": a.suppressed,
            "rule_ids": a.rule_ids,
            "max_ml_score": a.max_ml_score,
            "ml_threshold": a.ml_threshold,
            "model_ids": a.model_ids,
            "rule_versions": a.rule_versions,
        }
        if not public:
            item["triage"] = [
                {
                    "by": t.actor_label,
                    "at": t.created_at.isoformat(),
                    "to": t.to_status,
                    "assessment": t.to_assessment,
                    "note": t.note[:500],
                }
                for t in a.triage.all()
            ]
        top.append(item)
    return {
        "kind": "alerts",
        "namespace": namespace,
        "range_days": days,
        "total_alerts": total,
        "by_source": dict(Counter(qs.values_list("detection_source", flat=True))),
        "by_severity": dict(Counter(qs.values_list("severity", flat=True))),
        "by_assessment": dict(Counter(qs.values_list("assessment", flat=True))),
        "sources": sources,
        "ml": ml,
        "alerts": top,
        "statement": (
            "Không có alert trong khoảng thời gian này. Điều đó không chứng minh không có mối đe dọa; xem tình trạng nguồn."
            if total == 0
            else f"{total} alert (đã nhóm). Số alert không phải số vụ tấn công."
        ),
        "limitations": _limitations(None),
    }


def render_markdown(data: dict[str, Any], public: bool) -> str:
    L: list[str] = []
    if public:
        L += [
            "> **DRAFT công khai — cần người review trước khi chia sẻ.** Entity/nguồn đã thay bằng alias; "
            "pseudonym/alias không phải ẩn danh tuyệt đối.",
            "",
        ]
    if data["kind"] == "experiment":
        e, d = data["experiment"], data["dataset"]
        L += [
            f"# Báo cáo thí nghiệm {md_escape(e['id'])}",
            "",
            f"- Dataset: {md_escape(d['id'])} — provenance **{d['provenance']}**, privacy {d['privacy_class']}, license: {md_escape(d['license'])}",
            f"- Protocol: {e['protocol_version']}; split manifest sha256 `{e['split_manifest_sha256'][:16]}…`",
            f"- Window: {data['window_config']}",
            "",
            "## Split",
            f"- {data['split']['split_method']}; purge gap {data['split']['purge_gap_seconds']} s",
            f"- Assignment: {data['split']['assignment']}",
            f"- Counts (windows per label): {json.dumps(data['split']['counts'], ensure_ascii=False)}",
            f"- Diagnostics: {json.dumps(data['split']['diagnostics'], ensure_ascii=False)}",
            "",
            "## Rules (current versions)",
            f"{data['rules']}",
            "",
        ]
        from .model_card import metrics_table

        for m in data["models"]:
            L += [
                f"## Model {md_escape(m['model_id'])} ({m['domain']})",
                f"- IsolationForest {m['hyperparameters']}; n_train={m['n_train']}; training {m['training_seconds']} s",
                f"- Threshold {m['threshold']:.4f} (v{m['threshold_version']}); criterion {m['threshold_criterion']}",
                f"- Score: {m['score_transform']}",
                "",
                "### Validation (T1_SUSPICIOUS)",
                metrics_table(m["validation"]),
                "### Validation (T2_ANOMALOUS)",
                metrics_table(m["validation"], "T2_ANOMALOUS"),
            ]
            for r in m["test_runs"]:
                flag = (
                    " — **test đã được xem trước đó (không còn unseen)**" if r["test_previously_seen"] else ""
                )
                L += [
                    f"### Test run {r['run_index']}{flag}",
                    "T1_SUSPICIOUS:",
                    metrics_table(r["metrics"]),
                    "T2_ANOMALOUS:",
                    metrics_table(r["metrics"], "T2_ANOMALOUS"),
                    f"Per-scenario (hybrid_or): {json.dumps(r['metrics']['tasks']['T1_SUSPICIOUS']['methods']['hybrid_or']['per_scenario'], ensure_ascii=False)}",
                    f"Timing: {r['metrics']['timing']}",
                    "",
                ]
        L += ["## So sánh", *[f"- {md_escape(x)}" for x in data["comparison"]], ""]
        L += ["## Tái tạo", "```", *data["reproduce"], "```", ""]
    else:
        L += [
            f"# Báo cáo alert — namespace {md_escape(data['namespace'])} ({data['range_days']} ngày)",
            "",
            data["statement"],
            "",
            f"- Theo nguồn phát hiện: {data['by_source']}",
            f"- Theo severity: {data['by_severity']}",
            f"- Theo đánh giá: {data['by_assessment']}",
            f"- ML: {data['ml']}",
            "",
            "## Nguồn",
        ]
        for s in data["sources"]:
            L.append(
                f"- {md_escape(s['source'])} ({s['type']}, {s['provenance']}): {s['health']}; last run {s['last_run']}"
            )
        L += [
            "",
            "## Alerts gần nhất",
            "| ID | Domain | Entity | Cửa sổ | Nguồn | Sev | Tiêu đề | Triage |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for a in data["alerts"]:
            L.append(
                f"| {a['id']} | {a['domain']} | {md_escape(a['entity'])} | {a['window_start'][:19]} | {a['detection_source']} | "
                f"{a['severity']} | {md_escape(a['title'])} | {a['workflow']}/{a['assessment']} |"
            )
    L += ["", "## Giới hạn", *[f"- {x}" for x in data["limitations"]], ""]
    return "\n".join(L)


def export_report(params: dict[str, Any], actor=None) -> dict[str, Any]:
    public = bool(params.get("public_draft"))
    alias = Aliaser(public)
    if params.get("experiment"):
        data = experiment_data(Experiment.objects.get(exp_id=params["experiment"]), alias)
    else:
        data = alerts_data(params.get("namespace", "live"), int(params.get("days", 30)), alias, public)
    data["generated_at"] = timezone.now().isoformat()
    data["public_draft"] = public
    rid = f"{data['kind']}-{timezone.now():%Y%m%d%H%M%S}-{hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:6]}"
    base = (get_config().public_drafts_dir if public else get_config().reports_dir) / rid
    base.mkdir(parents=True, exist_ok=True)
    md = render_markdown(data, public)
    js = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    page = render_to_string("reports/report_file.html", {"md": md, "data": data, "title": rid})
    files = {}
    for ext, content in (("md", md), ("json", js), ("html", page)):
        p = base / f"report.{ext}"
        p.write_text(content, encoding="utf-8")
        files[ext] = {"rel": f"{rid}/report.{ext}", "sha256": hashlib.sha256(content.encode()).hexdigest()}
    Report.objects.create(
        report_id=rid,
        kind=data["kind"],
        params=params,
        public_draft=public,
        files=files,
        created_by=actor if getattr(actor, "is_authenticated", False) else None,
    )
    audit(actor, "report.export", "report", rid, "", public_draft=public, params=params)
    return {"report_id": rid, "files": {k: v["rel"] for k, v in files.items()}, "public_draft": public}


def escape(s: str) -> str:
    return html.escape(s)
