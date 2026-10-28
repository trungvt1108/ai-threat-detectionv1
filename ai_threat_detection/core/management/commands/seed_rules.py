from django.core.management.base import BaseCommand

from ai_threat_detection.accounts.roles import ensure_groups
from ai_threat_detection.rules.service import ensure_default_rules


class Command(BaseCommand):
    help = "Seed the default rule pack (version 1 of rules not yet present) and role groups. Never overwrites edits."

    def handle(self, *a, **o):
        ensure_groups()
        n = ensure_default_rules()
        self.stdout.write(f"rules seeded: {n}")
