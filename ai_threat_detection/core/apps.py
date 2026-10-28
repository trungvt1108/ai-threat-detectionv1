from django.apps import AppConfig
from django.db.models.signals import post_migrate


def _seed(sender, **kwargs):
    from ai_threat_detection.accounts.roles import ensure_groups
    from ai_threat_detection.rules.service import ensure_default_rules

    ensure_groups()
    ensure_default_rules()


class CoreConfig(AppConfig):
    name = "ai_threat_detection.core"
    label = "atd_core"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        post_migrate.connect(_seed, sender=self, dispatch_uid="atd_seed_defaults")
