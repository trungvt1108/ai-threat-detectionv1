from django.apps import AppConfig


class WorkerConfig(AppConfig):
    name = "ai_threat_detection.worker"
    label = "atd_worker"
    default_auto_field = "django.db.models.BigAutoField"
