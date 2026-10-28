"""Console views. Every view enforces its role server-side (deny by default);
GET never changes state; mutations are POST + CSRF + Origin-checked."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import FileResponse, Http404, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from ai_threat_detection.accounts.roles import can_view_raw_identity, has_role, role_required
from ai_threat_detection.alerts.models import (
    Alert,
    AlertDecision,
    Assessment,
    DetectionSource,
    Notification,
    Suppression,
    WorkflowStatus,
)
from ai_threat_detection.alerts.triage import TriageError, create_suppression, revoke_suppression, triage
from ai_threat_detection.conf import get_config
from ai_threat_detection.core.audit import audit
from ai_threat_detection.core.models import AuditLog
from ai_threat_detection.experiments.models import Dataset, EvaluationRun, Experiment
from ai_threat_detection.features.drift import drift_report
from ai_threat_detection.features.models import DetectionCheckpoint
from ai_threat_detection.registry import service as registry
from ai_threat_detection.registry.models import ActivationHistory, ActiveModel, ModelVersion
from ai_threat_detection.reports.models import Report
from ai_threat_detection.rules.engine import RuleValidationError
from ai_threat_detection.rules.models import RuleConfig
from ai_threat_detection.rules.service import update_rule
from ai_threat_detection.sources.adapters.registry import get_adapter
from ai_threat_detection.sources.models import (
    Event,
    IngestRun,
    RawIdentity,
    RejectedRecord,
    Source,
    SourceHealth,
)
from ai_threat_detection.sources.paths import (
    PathNotAllowedError,
    list_source_files,
    resolve_source_file,
    validate_source_root,
)
from ai_threat_detection.worker.models import Job
from ai_threat_detection.worker.runner import enqueue, request_cancel

from . import forms

SEVERITIES = ["high", "medium", "low", "info"]
PAGE = 50


def _ml_states():
    out = {}
    for d in ("AUTH", "HTTP"):
        det = registry.get_active_detector(d)
        out[d] = {"status": det.status, "reason": det.reason, "model": det.model_version}
    return out


@role_required("viewer")
def overview(request):
    now = timezone.now()
    since = now - timedelta(days=1)
    live = Alert.objects.filter(namespace="live")
    ctx = {
        "sources": Source.objects.select_related("health").exclude(name__startswith="ds-").order_by("name"),
        "ml": _ml_states(),
        "alerts_24h": live.filter(created_at__gte=since).count(),
        "alerts_open": live.exclude(workflow_status="CLOSED").count(),
        "by_source": live.filter(created_at__gte=since)
        .values("detection_source")
        .annotate(n=Count("id"))
        .order_by("-n"),
        "by_severity": live.exclude(workflow_status="CLOSED").values("severity").annotate(n=Count("id")),
        "recent_alerts": Alert.objects.order_by("-created_at")[:8],
        "recent_runs": IngestRun.objects.select_related("source").order_by("-started_at")[:6],
        "active_jobs": Job.objects.filter(status__in=["QUEUED", "RUNNING", "CANCEL_REQUESTED"]).count(),
        "rule_count": RuleConfig.objects.filter(is_current=True, enabled=True).count(),
        "namespaces": Alert.objects.values("namespace").annotate(n=Count("id")).order_by("namespace"),
    }
    return render(request, "ui/overview.html", ctx)


@role_required("viewer")
def sources(request):
    form = None
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            return HttpResponseForbidden("Không đủ quyền cho thao tác này.")
        form = forms.SourceForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            try:
                root = validate_source_root(cd["root_path"])
            except PathNotAllowedError as exc:
                form.add_error("root_path", str(exc))
            else:
                from ai_threat_detection.normalization.timeparse import validate_timezone

                if cd["assume_timezone"] and not validate_timezone(cd["assume_timezone"]):
                    form.add_error("assume_timezone", "timezone không hợp lệ")
                elif Source.objects.filter(name=cd["name"]).exists():
                    form.add_error("name", "đã tồn tại")
                else:
                    src = Source.objects.create(
                        name=cd["name"],
                        source_type=cd["source_type"],
                        root_path=str(root),
                        file_pattern=cd["file_pattern"] or get_adapter(cd["source_type"]).default_pattern,
                        provenance=cd["provenance"],
                        privacy_class=cd["privacy_class"],
                        assume_timezone=cd["assume_timezone"],
                        sensor_name=cd["sensor_name"],
                        stale_after_seconds=cd["stale_after_seconds"],
                        expected_max_gap_seconds=cd["expected_max_gap_seconds"],
                        license_note=cd["license_note"],
                        created_by=request.user,
                    )
                    audit(
                        request.user,
                        "source.register",
                        "source",
                        src.name,
                        cd["reason"],
                        type=src.source_type,
                        provenance=src.provenance,
                        privacy=src.privacy_class,
                        tz=src.assume_timezone,
                    )
                    messages.success(request, f"Đã đăng ký nguồn {src.name}.")
                    return redirect("source_detail", name=src.name)
    srcs = Source.objects.select_related("health").annotate(n_events=Count("events")).order_by("name")
    return render(
        request,
        "ui/sources.html",
        {
            "sources": srcs,
            "form": form or forms.SourceForm(),
            "allowed_roots_count": len(get_config().allowed_source_roots),
        },
    )


@role_required("viewer")
def source_detail(request, name):
    src = get_object_or_404(Source, name=name)
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            return HttpResponseForbidden("Không đủ quyền cho thao tác này.")
        f = forms.SourceJobForm(request.POST)
        if f.is_valid():
            cd = f.cleaned_data
            try:
                resolve_source_file(src.root_path, cd["file"], src.file_pattern)
            except PathNotAllowedError as exc:
                messages.error(request, f"File không hợp lệ: {exc}")
                return redirect("source_detail", name=name)
            params = {"source": src.name, "file": cd["file"]}
            if cd["action"] == "replay":
                params["speed"] = cd.get("speed") or 0.0
            if cd["action"] == "follow":
                params["duration_s"] = cd.get("duration") or 60
            try:
                job = enqueue(cd["action"], params, request.user)
            except ValueError as exc:
                messages.error(request, str(exc))
            else:
                audit(request.user, f"job.enqueue.{cd['action']}", "job", job.pk, "", source=src.name)
                messages.success(
                    request,
                    f"Đã xếp hàng job #{job.pk} ({cd['action']}). Chạy 'manage.py runworker' để thực thi.",
                )
            return redirect("source_detail", name=name)
    try:
        files = list_source_files(src.root_path, src.file_pattern, limit=200)
        files_error = ""
    except PathNotAllowedError as exc:
        files, files_error = [], str(exc)
    reasons = (
        RejectedRecord.objects.filter(source=src).values("reason").annotate(n=Count("id")).order_by("-n")
    )
    flows = Event.objects.filter(source=src).values("domain").annotate(n=Count("id"))
    from ai_threat_detection.sources.adapters.registry import get_adapter

    ctx = {
        "src": src,
        "health": SourceHealth.objects.filter(source=src).first(),
        "runs": IngestRun.objects.filter(source=src)[:20],
        "reasons": reasons,
        "files": files,
        "files_error": files_error,
        "domains": flows,
        "adapter": get_adapter(src.source_type),
        "job_form": forms.SourceJobForm(),
        "show_root": has_role(request.user, "admin"),
    }
    return render(request, "ui/source_detail.html", ctx)


@role_required("viewer")
def datasets(request):
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            return HttpResponseForbidden("Không đủ quyền cho thao tác này.")
        action = request.POST.get("action")
        if action == "synthetic":
            f = forms.SyntheticForm(request.POST)
            if f.is_valid():
                job = enqueue(
                    "generate_synthetic",
                    {
                        "dataset_id": f.cleaned_data["dataset_id"],
                        "seed": f.cleaned_data["seed"],
                        "n_captures": f.cleaned_data["captures"],
                    },
                    request.user,
                )
                messages.success(request, f"Job #{job.pk}: tạo dataset SYNTHETIC_DEMO.")
            else:
                messages.error(request, "Tham số không hợp lệ.")
        elif action == "lab":
            f = forms.LabForm(request.POST)
            if f.is_valid():
                job = enqueue("lab_capture", f.cleaned_data, request.user, timeout_seconds=1800)
                messages.success(request, f"Job #{job.pk}: lab capture (fixture loopback).")
            else:
                messages.error(request, "Tham số không hợp lệ.")
        elif action == "import":
            ds_id = request.POST.get("dataset_id", "")
            job = enqueue("import_dataset", {"dataset": ds_id}, request.user)
            messages.success(request, f"Job #{job.pk}: import dataset {ds_id}.")
        elif action == "detect":
            ds = get_object_or_404(Dataset, dataset_id=request.POST.get("dataset_id", ""))
            job = enqueue("detect", {"dataset": ds.dataset_id, "finalize": True}, request.user)
            messages.success(request, f"Job #{job.pk}: chạy phát hiện trên mọi capture của {ds.dataset_id}.")
            return redirect("dataset_detail", dataset_id=ds.dataset_id)
        return redirect("datasets")
    on_disk = []
    ddir = get_config().datasets_dir
    if ddir.exists():
        registered = set(Dataset.objects.values_list("dataset_id", flat=True))
        on_disk = sorted(
            p.name for p in ddir.iterdir() if (p / "dataset.json").exists() and p.name not in registered
        )
    return render(
        request,
        "ui/datasets.html",
        {
            "datasets": Dataset.objects.annotate(n_captures=Count("captures")),
            "unregistered": on_disk,
            "synthetic_form": forms.SyntheticForm(),
            "lab_form": forms.LabForm(),
        },
    )


@role_required("viewer")
def dataset_detail(request, dataset_id):
    ds = get_object_or_404(Dataset, dataset_id=dataset_id)
    return render(
        request,
        "ui/dataset_detail.html",
        {
            "ds": ds,
            "captures": ds.captures.all(),
            "experiments": ds.experiments.all(),
            "exp_form": forms.ExperimentForm(),
        },
    )


@role_required("viewer")
def jobs(request):
    qs = Job.objects.all()
    st = request.GET.get("status")
    if st:
        qs = qs.filter(status=st)
    page = Paginator(qs, PAGE).get_page(request.GET.get("page"))
    return render(
        request, "ui/jobs.html", {"page": page, "status": st, "statuses": [s for s, _ in Job.STATUSES]}
    )


@role_required("viewer")
def jobs_status(request):
    ids = [int(x) for x in request.GET.get("ids", "").split(",") if x.isdigit()][:50]
    data = {
        j.pk: {"status": j.status, "progress": j.progress, "error": j.error}
        for j in Job.objects.filter(pk__in=ids)
    }
    return JsonResponse({"jobs": data})


@require_POST
@role_required("analyst")
def job_cancel(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    if job.created_by_id != request.user.pk and not has_role(request.user, "admin"):
        messages.error(request, "Chỉ người tạo job hoặc admin được dừng job.")
    elif request_cancel(job, request.user):
        messages.success(request, f"Đã yêu cầu dừng job #{job.pk}.")
    else:
        messages.info(request, "Job không còn chạy.")
    return redirect("jobs")


def _alert_filters(request):
    qs = Alert.objects.all()
    g = request.GET
    f = {
        k: g.get(k, "")
        for k in (
            "namespace",
            "domain",
            "source",
            "severity",
            "status",
            "assessment",
            "entity",
            "q",
            "since",
            "until",
            "suppressed",
            "sort",
        )
    }
    if f["namespace"]:
        qs = qs.filter(namespace=f["namespace"])
    if f["domain"]:
        qs = qs.filter(domain=f["domain"])
    if f["source"]:
        qs = qs.filter(detection_source=f["source"])
    if f["severity"]:
        qs = qs.filter(severity=f["severity"])
    if f["status"]:
        qs = qs.filter(workflow_status=f["status"])
    if f["assessment"]:
        qs = qs.filter(assessment=f["assessment"])
    if f["entity"]:
        qs = qs.filter(entity_key=f["entity"][:40])
    if f["q"]:
        qs = qs.filter(Q(title__icontains=f["q"][:100]) | Q(rule_ids__icontains=f["q"][:20]))
    for key, op in (("since", "gte"), ("until", "lte")):
        if f[key]:
            try:
                dt = datetime.fromisoformat(f[key])
                if timezone.is_naive(dt):
                    dt = dt.replace(tzinfo=UTC)
                qs = qs.filter(**{f"window_end__{op}": dt})
            except ValueError:
                pass
    if f["suppressed"] != "1":
        qs = qs.filter(suppressed=False)
    order = {
        "new": "-window_end",
        "old": "window_end",
        "score": "-max_ml_score",
        "count": "-decision_count",
    }.get(f["sort"], "-window_end")
    return qs.order_by(order, "-id"), f


@role_required("viewer")
def alerts(request):
    qs, f = _alert_filters(request)
    page = Paginator(qs, PAGE).get_page(request.GET.get("page"))
    params = request.GET.copy()
    params.pop("page", None)
    return render(
        request,
        "ui/alerts.html",
        {
            "page": page,
            "f": f,
            "qs_params": params.urlencode(),
            "severities": SEVERITIES,
            "sources": DetectionSource.choices,
            "statuses": WorkflowStatus.choices,
            "assessments": Assessment.choices,
            "namespaces": Alert.objects.values_list("namespace", flat=True).distinct().order_by("namespace"),
            "domains": ["AUTH", "HTTP", "EVE", "HEALTH"],
        },
    )


def _event_rows(ids, raw: bool):
    rows = []
    for ev in Event.objects.filter(event_id__in=ids).order_by("event_time", "event_id")[:50]:
        row = {
            "time": ev.event_time,
            "domain": ev.domain,
            "entity": ev.entity_key,
            "user": ev.user_key,
            "fields": {k: v for k, v in ev.fields.items() if k not in ("user_key", "host_key", "peer_key")},
            "flags": ev.quality_flags,
            "provenance": ev.provenance,
            "locator": f"{ev.file_key[:8]}@{ev.offset}",
        }
        rows.append(row)
    if raw:
        keys = {r["entity"] for r in rows} | {r["user"] for r in rows}
        raw_map = dict(
            RawIdentity.objects.filter(pseudonym__in=[k for k in keys if k]).values_list(
                "pseudonym", "raw_value"
            )
        )
        for r in rows:
            r["entity_raw"] = raw_map.get(r["entity"])
            r["user_raw"] = raw_map.get(r["user"])
    return rows


@role_required("viewer")
def alert_detail(request, alert_id):
    alert = get_object_or_404(Alert, pk=alert_id)
    decisions = list(alert.decisions.select_related("window").order_by("window_start", "id")[:200])
    show_raw = request.GET.get("raw") == "1" and can_view_raw_identity(request.user)
    if show_raw:
        audit(request.user, "raw_identity.view", "alert", alert.pk, "")
    ids = []
    for d in decisions:
        if d.window_id:
            ids.extend(d.window.sample_event_ids[:10])
        elif d.upstream_event_id:
            ids.append(d.upstream_event_id)
    latest = decisions[-1] if decisions else None
    correlated = []
    if alert.entity_key and alert.domain in ("AUTH", "HTTP"):
        lo, hi = alert.window_start - timedelta(minutes=10), alert.window_end + timedelta(minutes=10)
        correlated = list(
            AlertDecision.objects.filter(
                alert__entity_key=alert.entity_key,
                detection_source="UPSTREAM_IDS",
                window_start__gte=lo,
                window_start__lte=hi,
            ).select_related("alert")[:20]
        )
    return render(
        request,
        "ui/alert_detail.html",
        {
            "alert": alert,
            "decisions": decisions,
            "latest": latest,
            "events": _event_rows(ids, show_raw),
            "triage_form": forms.TriageForm(
                initial={"to_status": alert.workflow_status, "to_assessment": alert.assessment}
            ),
            "suppress_form": forms.SuppressionForm(initial={"rule_id": (alert.rule_ids or [""])[0]}),
            "triage": alert.triage.all(),
            "can_raw": can_view_raw_identity(request.user),
            "show_raw": show_raw,
            "correlated": correlated,
            "explanation_json": json.dumps(
                latest.explanation if latest else {}, indent=1, ensure_ascii=False, default=str
            ),
        },
    )


@require_POST
@role_required("analyst")
def alert_triage(request, alert_id):
    alert = get_object_or_404(Alert, pk=alert_id)
    f = forms.TriageForm(request.POST)
    if f.is_valid():
        try:
            triage(
                alert,
                request.user,
                f.cleaned_data["to_status"],
                f.cleaned_data["to_assessment"],
                f.cleaned_data["note"],
            )
            messages.success(request, "Đã ghi nhận triage.")
        except TriageError as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, "Dữ liệu triage không hợp lệ.")
    return redirect("alert_detail", alert_id=alert.pk)


@require_POST
@role_required("analyst")
def alert_suppress(request, alert_id):
    alert = get_object_or_404(Alert, pk=alert_id)
    f = forms.SuppressionForm(request.POST)
    if f.is_valid():
        cd = f.cleaned_data
        try:
            create_suppression(
                request.user,
                domain=alert.domain,
                entity_key=alert.entity_key,
                rule_id=cd["rule_id"] if cd["scope"] == "rule" else "",
                reason=cd["reason"],
                days=cd["days"],
            )
            messages.success(
                request, "Đã tạo suppression có thời hạn (alert mới vẫn được lưu và hiển thị khi lọc)."
            )
        except TriageError as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, "Lý do tối thiểu 10 ký tự, thời hạn 1–30 ngày.")
    return redirect("alert_detail", alert_id=alert.pk)


@role_required("viewer")
def models_list(request):
    return render(
        request,
        "ui/models.html",
        {
            "models": ModelVersion.objects.select_related("experiment").all(),
            "ml": _ml_states(),
            "active": {am.domain: am for am in ActiveModel.objects.select_related("model")},
            "history": ActivationHistory.objects.select_related("model", "previous")[:30],
        },
    )


@role_required("viewer")
def model_detail(request, model_id):
    mv = get_object_or_404(ModelVersion, model_id=model_id)
    card = ""
    if mv.model_card_rel:
        p = registry.models_root() / mv.model_card_rel
        if p.exists():
            card = p.read_text(encoding="utf-8")
    return render(
        request,
        "ui/model_detail.html",
        {
            "mv": mv,
            "card": card,
            "evals": EvaluationRun.objects.filter(model=mv),
            "reason_form": forms.ReasonForm(),
            "threshold_form": forms.ThresholdForm(initial={"threshold": mv.threshold}),
            "is_active": ActiveModel.objects.filter(domain=mv.domain, model=mv).exists(),
            "val_json": json.dumps(mv.validation_metrics.get("tasks", {}), default=str),
            "test_json": json.dumps(mv.test_metrics.get("tasks", {}), default=str),
        },
    )


@require_POST
@role_required("admin")
def model_action(request, model_id):
    mv = get_object_or_404(ModelVersion, model_id=model_id)
    action = request.POST.get("action")
    form = forms.ThresholdForm(request.POST) if action == "threshold" else forms.ReasonForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Cần lý do (>= 5 ký tự) và giá trị hợp lệ.")
        return redirect("model_detail", model_id=model_id)
    reason = form.cleaned_data["reason"]
    try:
        if action == "activate":
            registry.activate(mv.model_id, request.user, reason)
            messages.success(request, f"Đã kích hoạt {mv.model_id}.")
        elif action == "rollback":
            prev = registry.rollback(mv.domain, request.user, reason)
            messages.success(request, f"Đã rollback {mv.domain} về {prev.model_id}.")
        elif action == "deactivate":
            registry.deactivate(mv.domain, request.user, reason)
            messages.success(request, f"{mv.domain}: không còn model active (rules-only).")
        elif action == "threshold":
            registry.set_threshold(mv.model_id, form.cleaned_data["threshold"], request.user, reason)
            messages.success(request, "Đã đổi threshold (có version + audit).")
        else:
            messages.error(request, "Thao tác không hợp lệ.")
    except (ValueError, registry.ModelLoadError) as exc:
        messages.error(request, f"Không thực hiện được: {exc}")
    return redirect("model_detail", model_id=model_id)


@role_required("viewer")
def experiments(request):
    return render(
        request, "ui/experiments.html", {"experiments": Experiment.objects.select_related("dataset")}
    )


@role_required("viewer")
def experiment_detail(request, exp_id):
    exp = get_object_or_404(Experiment, exp_id=exp_id)
    manifest = {}
    p = get_config().experiments_dir / exp.split_manifest_rel
    if exp.split_manifest_rel and p.is_file():
        manifest = json.loads(p.read_text(encoding="utf-8"))
    models = ModelVersion.objects.filter(experiment=exp)
    evals = EvaluationRun.objects.filter(experiment=exp).select_related("model")
    chart = []
    for ev in evals:
        t1 = ev.metrics.get("tasks", {}).get("T1_SUSPICIOUS", {}).get("methods", {})
        chart.append(
            {
                "label": f"{ev.domain} {ev.split} #{ev.run_index}",
                "values": {m: v.get("f1") for m, v in t1.items()},
            }
        )
    return render(
        request,
        "ui/experiment_detail.html",
        {
            "exp": exp,
            "manifest": manifest,
            "models": models,
            "evals": evals,
            "chart": chart,
            "reason_form": forms.ReasonForm(),
        },
    )


@require_POST
@role_required("admin")
def experiment_action(request, exp_id):
    action = request.POST.get("action")
    if action == "create":
        ds = get_object_or_404(Dataset, dataset_id=exp_id)
        f = forms.ExperimentForm(request.POST)
        if f.is_valid():
            cd = f.cleaned_data
            job = enqueue(
                "create_experiment",
                {
                    "dataset": ds.dataset_id,
                    "exp_id": cd["exp_id"],
                    "window": {
                        "size_s": cd["window_size"],
                        "stride_s": cd["window_size"],
                        "allowed_lateness_s": cd["lateness"],
                    },
                    "counts": cd["counts"],
                    "feature_sets": {"AUTH": "auth_v1", "HTTP": cd["http_feature_set"]},
                },
                request.user,
            )
            messages.success(request, f"Job #{job.pk}: tạo experiment {cd['exp_id']}.")
        else:
            messages.error(request, f"Tham số không hợp lệ: {f.errors.as_text()}")
        return redirect("dataset_detail", dataset_id=ds.dataset_id)
    exp = get_object_or_404(Experiment, exp_id=exp_id)
    domain = request.POST.get("domain")
    if domain not in ("AUTH", "HTTP"):
        messages.error(request, "Domain không hợp lệ.")
        return redirect("experiment_detail", exp_id=exp_id)
    if action == "train":
        job = enqueue(
            "train",
            {
                "experiment": exp.exp_id,
                "domain": domain,
                "train_on_unknown": request.POST.get("train_on_unknown") == "1",
            },
            request.user,
        )
        messages.success(request, f"Job #{job.pk}: train {domain} (một training job tại một thời điểm).")
    elif action == "evaluate":
        model_id = request.POST.get("model_id", "")
        mv = get_object_or_404(ModelVersion, model_id=model_id, experiment=exp, domain=domain)
        job = enqueue(
            "evaluate",
            {
                "experiment": exp.exp_id,
                "domain": domain,
                "model_id": mv.model_id,
                "rerun_reason": request.POST.get("rerun_reason", "")[:500],
            },
            request.user,
        )
        messages.success(request, f"Job #{job.pk}: evaluate test {domain}.")
    return redirect("experiment_detail", exp_id=exp_id)


@role_required("viewer")
def drift(request):
    ns = request.GET.get("namespace", "live")[:100]
    reports = [drift_report(d, namespace=ns) for d in ("AUTH", "HTTP")]
    runs = IngestRun.objects.filter(namespace=ns).select_related("source")[:20]
    checkpoints = DetectionCheckpoint.objects.filter(namespace=ns)
    return render(
        request,
        "ui/drift.html",
        {
            "reports": reports,
            "runs": runs,
            "checkpoints": checkpoints,
            "namespace": ns,
            "namespaces": IngestRun.objects.values_list("namespace", flat=True).distinct(),
        },
    )


@role_required("viewer")
def reports(request):
    if request.method == "POST":
        if not has_role(request.user, "analyst"):
            return HttpResponseForbidden("Không đủ quyền cho thao tác này.")
        f = forms.ReportForm(request.POST)
        if f.is_valid():
            cd = f.cleaned_data
            params = {"public_draft": cd["public_draft"], "namespace": cd["namespace"], "days": cd["days"]}
            if cd["kind"] == "experiment":
                if not Experiment.objects.filter(exp_id=cd["experiment"]).exists():
                    messages.error(request, "Experiment không tồn tại.")
                    return redirect("reports")
                params["experiment"] = cd["experiment"]
            job = enqueue("report", params, request.user)
            messages.success(request, f"Job #{job.pk}: xuất báo cáo.")
        return redirect("reports")
    return render(
        request,
        "ui/reports.html",
        {
            "reports": Report.objects.all()[:100],
            "form": forms.ReportForm(),
            "experiments": Experiment.objects.values_list("exp_id", flat=True),
        },
    )


@role_required("viewer")
def report_file(request, report_id, fmt):
    rep = get_object_or_404(Report, report_id=report_id)
    if fmt not in ("md", "json", "html") or fmt not in rep.files:
        raise Http404
    if not rep.public_draft and not has_role(request.user, "analyst"):
        return HttpResponseForbidden("Không đủ quyền cho thao tác này.")
    base = (get_config().public_drafts_dir if rep.public_draft else get_config().reports_dir).resolve()
    path = (base / rep.files[fmt]["rel"]).resolve()
    try:
        path.relative_to(base)
    except ValueError:
        raise Http404 from None
    if not path.exists():
        raise Http404
    ctype = {
        "md": "text/markdown; charset=utf-8",
        "json": "application/json",
        "html": "text/html; charset=utf-8",
    }[fmt]
    resp = FileResponse(
        open(path, "rb"),
        content_type=ctype,
        as_attachment=request.GET.get("download") == "1",
        filename=f"{report_id}.{fmt}",
    )
    if fmt == "html":
        resp["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
        )
    audit(request.user, "report.view", "report", report_id, "", fmt=fmt)
    return resp


@role_required("admin")
def audit_log(request):
    page = Paginator(AuditLog.objects.all(), PAGE).get_page(request.GET.get("page"))
    return render(request, "ui/audit.html", {"page": page})


@role_required("viewer")
def settings_page(request):
    from django.contrib.auth import get_user_model

    from ai_threat_detection.accounts.roles import user_role

    cfg = get_config()
    users = (
        [(u.username, user_role(u)) for u in get_user_model().objects.all()]
        if has_role(request.user, "admin")
        else []
    )
    return render(
        request,
        "ui/settings.html",
        {
            "rules": RuleConfig.objects.filter(is_current=True).order_by("rule_id"),
            "suppressions": Suppression.objects.select_related("actor").all()[:100],
            "now": timezone.now(),
            "cfg": cfg,
            "users": users,
        },
    )


@role_required("admin")
def rule_edit(request, rule_id):
    rc = get_object_or_404(RuleConfig, rule_id=rule_id, is_current=True)
    if request.method == "POST":
        f = forms.RuleEditForm(request.POST)
        if f.is_valid():
            try:
                d = json.loads(f.cleaned_data["definition"])
                d.pop("version", None)
                update_rule(rule_id, d, f.cleaned_data["enabled"], request.user, f.cleaned_data["reason"])
                messages.success(request, f"{rule_id}: đã tạo version mới.")
                return redirect("settings")
            except (json.JSONDecodeError, RuleValidationError) as exc:
                f.add_error("definition", str(exc))
    else:
        d = dict(rc.definition)
        d.pop("version", None)
        f = forms.RuleEditForm(
            initial={"definition": json.dumps(d, indent=2, ensure_ascii=False), "enabled": rc.enabled}
        )
    return render(
        request,
        "ui/rule_edit.html",
        {"rc": rc, "form": f, "history": RuleConfig.objects.filter(rule_id=rule_id).order_by("-version")},
    )


@require_POST
@role_required("analyst")
def suppression_revoke(request, sid):
    s = get_object_or_404(Suppression, pk=sid)
    if s.actor_id != request.user.pk and not has_role(request.user, "admin"):
        messages.error(request, "Chỉ người tạo hoặc admin được thu hồi.")
    elif s.revoked_at is None:
        revoke_suppression(s, request.user)
        messages.success(request, "Đã thu hồi suppression.")
    return redirect("settings")


@role_required("viewer")
def notifications(request):
    if request.method == "POST":
        if not has_role(request.user, "analyst"):
            return HttpResponseForbidden("Không đủ quyền cho thao tác này.")
        Notification.objects.filter(read_at__isnull=True).update(read_at=timezone.now())
        return redirect("notifications")
    return render(
        request, "ui/notifications.html", {"items": Notification.objects.select_related("alert")[:100]}
    )
