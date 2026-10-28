from django.core.management.base import BaseCommand

from ai_threat_detection.conf import get_config
from ai_threat_detection.normalization.keys import (
    DJANGO_KEY,
    INTEGRITY_KEY,
    PSEUDONYM_KEY,
    create_key,
    key_status,
)


class Command(BaseCommand):
    help = "Create .local runtime folders and local key files (never overwrites existing keys)."

    def handle(self, *args, **opts):
        cfg = get_config()
        for d in cfg.managed_dirs():
            d.mkdir(parents=True, exist_ok=True)
        for name in (DJANGO_KEY, PSEUDONYM_KEY, INTEGRITY_KEY):
            _, created = create_key(name)
            self.stdout.write(f"{name}: " + ("created" if created else "exists"))
        for name in (PSEUDONYM_KEY, INTEGRITY_KEY):
            st = key_status(name)
            self.stdout.write(f"{name} key_id={st.get('key_id', 'MISSING')}")
        self.stdout.write(
            "Next: python manage.py migrate ; python manage.py create_user --username <name> --role admin"
        )
