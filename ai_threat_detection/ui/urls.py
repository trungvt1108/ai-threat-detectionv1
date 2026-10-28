from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="ui/login.html", redirect_authenticated_user=True),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", views.overview, name="overview"),
    path("sources/", views.sources, name="sources"),
    path("sources/<slug:name>/", views.source_detail, name="source_detail"),
    path("datasets/", views.datasets, name="datasets"),
    path("datasets/<slug:dataset_id>/", views.dataset_detail, name="dataset_detail"),
    path("jobs/", views.jobs, name="jobs"),
    path("jobs/status.json", views.jobs_status, name="jobs_status"),
    path("jobs/<int:job_id>/cancel/", views.job_cancel, name="job_cancel"),
    path("alerts/", views.alerts, name="alerts"),
    path("alerts/<int:alert_id>/", views.alert_detail, name="alert_detail"),
    path("alerts/<int:alert_id>/triage/", views.alert_triage, name="alert_triage"),
    path("alerts/<int:alert_id>/suppress/", views.alert_suppress, name="alert_suppress"),
    path("models/", views.models_list, name="models"),
    path("models/<slug:model_id>/", views.model_detail, name="model_detail"),
    path("models/<slug:model_id>/action/", views.model_action, name="model_action"),
    path("experiments/", views.experiments, name="experiments"),
    path("experiments/<slug:exp_id>/", views.experiment_detail, name="experiment_detail"),
    path("experiments/<slug:exp_id>/action/", views.experiment_action, name="experiment_action"),
    path("drift/", views.drift, name="drift"),
    path("reports/", views.reports, name="reports"),
    path("reports/<str:report_id>/<str:fmt>/", views.report_file, name="report_file"),
    path("audit/", views.audit_log, name="audit"),
    path("settings/", views.settings_page, name="settings"),
    path("settings/rules/<str:rule_id>/", views.rule_edit, name="rule_edit"),
    path("settings/suppressions/<int:sid>/revoke/", views.suppression_revoke, name="suppression_revoke"),
    path("notifications/", views.notifications, name="notifications"),
]
