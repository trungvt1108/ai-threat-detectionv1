import json
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from ai_threat_detection.conf import get_config


class Command(BaseCommand):
    help = (
        "Retention cleanup of normalized events / rejected records / windows without alerts older than "
        "ATD_RETENTION_DAYS. Dry-run unless --apply. Never touches source log files or other projects."
    )

    def add_arguments(self, p):
        p.add_argument("--apply", action="store_true")
        p.add_argument("--days", type=int, default=None)
        p.add_argument("--namespace-prefix", default="", help="e.g. 'replay:' to clean only replays")

    def handle(self, *a, **o):
        from ai_threat_detection.features.models import FeatureWindow
        from ai_threat_detection.sources.models import Event, RejectedRecord

        days = o["days"] or get_config().retention_days
        cutoff = timezone.now() - timedelta(days=days)
        ev = Event.objects.filter(ingested_at__lt=cutoff)
        rej = RejectedRecord.objects.filter(created_at__lt=cutoff)
        fw = FeatureWindow.objects.filter(created_at__lt=cutoff, alertdecision__isnull=True)
        if o["namespace_prefix"]:
            ev = ev.filter(namespace__startswith=o["namespace_prefix"])
            rej = rej.filter(namespace__startswith=o["namespace_prefix"])
            fw = fw.filter(namespace__startswith=o["namespace_prefix"])
        db = get_config().db_path
        plan = {
            "cutoff": cutoff.isoformat(),
            "events": ev.count(),
            "rejected_records": rej.count(),
            "windows_without_alerts": fw.count(),
            "kept": "alerts and their decisions/windows, models, experiments, audit log",
            "db_bytes": db.stat().st_size if db.exists() else None,
        }
        if o["apply"]:
            with transaction.atomic():
                plan["deleted"] = {
                    "events": ev.delete()[0],
                    "rejected": rej.delete()[0],
                    "windows": fw.delete()[0],
                }
        else:
            plan["dry_run"] = True
        self.stdout.write(json.dumps(plan, indent=2))
