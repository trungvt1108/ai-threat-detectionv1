from django.core.management.base import BaseCommand, CommandError

from ai_threat_detection.registry.service import ModelLoadError, activate, set_threshold


class Command(BaseCommand):
    help = "Activate a registered candidate model (integrity/compatibility gate + audit). Optionally change its threshold."

    def add_arguments(self, p):
        p.add_argument("--model", required=True)
        p.add_argument("--reason", required=True)
        p.add_argument(
            "--threshold", type=float, default=None, help="manual threshold override (audited, versioned)"
        )

    def handle(self, *a, **o):
        try:
            if o["threshold"] is not None:
                set_threshold(o["model"], o["threshold"], "cli", o["reason"])
            mv = activate(o["model"], "cli", o["reason"])
        except (ValueError, ModelLoadError) as exc:
            raise CommandError(str(exc))
        self.stdout.write(
            f"active {mv.domain}: {mv.model_id} (threshold {mv.threshold:.4f} v{mv.threshold_version})"
        )
