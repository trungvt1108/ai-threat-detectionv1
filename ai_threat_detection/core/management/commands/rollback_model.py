from django.core.management.base import BaseCommand, CommandError

from ai_threat_detection.registry.service import ModelLoadError, deactivate, rollback


class Command(BaseCommand):
    help = "Roll back a domain to the previously active model, or --deactivate to fall back to rules-only."

    def add_arguments(self, p):
        p.add_argument("--domain", required=True, choices=["AUTH", "HTTP"])
        p.add_argument("--reason", required=True)
        p.add_argument("--deactivate", action="store_true")

    def handle(self, *a, **o):
        try:
            if o["deactivate"]:
                deactivate(o["domain"], "cli", o["reason"])
                self.stdout.write(f"{o['domain']}: no active model (rules-only, ML status UNTRAINED)")
                return
            mv = rollback(o["domain"], "cli", o["reason"])
        except (ValueError, ModelLoadError) as exc:
            raise CommandError(str(exc))
        self.stdout.write(f"rolled back {mv.domain} to {mv.model_id}")
