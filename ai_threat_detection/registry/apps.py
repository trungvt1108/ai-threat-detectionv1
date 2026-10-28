from django.apps import AppConfig


class RegistryConfig(AppConfig):
    name = "ai_threat_detection.registry"
    label = "atd_registry"
    default_auto_field = "django.db.models.BigAutoField"
