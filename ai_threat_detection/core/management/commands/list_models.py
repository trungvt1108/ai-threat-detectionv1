from django.core.management.base import BaseCommand

from ai_threat_detection.registry.models import ActiveModel, ModelVersion


class Command(BaseCommand):
    help = "List registered models (* = active for its domain)."

    def handle(self, *a, **o):
        active = {am.domain: am.model_id for am in ActiveModel.objects.all()}
        for mv in ModelVersion.objects.order_by("domain", "-created_at"):
            mark = "*" if active.get(mv.domain) == mv.pk else " "
            self.stdout.write(
                f"{mark} {mv.domain:5} {mv.model_id:42} {mv.status:10} thr={mv.threshold:.4f} n_train={mv.n_train}"
            )
