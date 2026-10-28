import json
import platform

from django.core.management.base import BaseCommand
from django.db import connection

from ai_threat_detection.conf import get_config
from ai_threat_detection.normalization.keys import INTEGRITY_KEY, PSEUDONYM_KEY, key_status


class Command(BaseCommand):
    help = (
        "Report Python/DB/key/parser/model/config states. Never prints secrets or reads outside the project."
    )

    def handle(self, *args, **opts):
        import django
        import numpy
        import sklearn
        import skops

        cfg = get_config()
        out: dict = {
            "python": platform.python_version(),
            "platform": platform.system(),
            "packages": {
                "django": django.__version__,
                "scikit-learn": sklearn.__version__,
                "numpy": numpy.__version__,
                "skops": skops.__version__,
            },
            "data_dir_exists": cfg.data_dir.exists(),
            "allowed_source_roots": len(cfg.allowed_source_roots),
            "max_cpu_threads": cfg.max_cpu_threads,
            "keys": [key_status(PSEUDONYM_KEY), key_status(INTEGRITY_KEY)],
        }
        for k in out["keys"]:
            k.pop("detail", None)
        try:
            from django.db.migrations.executor import MigrationExecutor

            with connection.cursor() as c:
                c.execute("PRAGMA journal_mode")
                out["db"] = {"ok": True, "journal_mode": c.fetchone()[0]}
            ex = MigrationExecutor(connection)
            out["db"]["pending_migrations"] = len(ex.migration_plan(ex.loader.graph.leaf_nodes()))
        except Exception as exc:  # noqa: BLE001
            out["db"] = {"ok": False, "error": type(exc).__name__}
        if out["db"].get("ok") and out["db"].get("pending_migrations") == 0:
            from ai_threat_detection.registry.service import get_active_detector
            from ai_threat_detection.rules.models import RuleConfig
            from ai_threat_detection.sources.adapters.registry import ADAPTERS
            from ai_threat_detection.sources.models import Source
            from ai_threat_detection.worker.models import Job

            out["parsers"] = {k: a.schema_version for k, a in ADAPTERS.items()}
            ml = {}
            for d in ("AUTH", "HTTP"):
                det = get_active_detector(d)
                ml[d] = {
                    "status": det.status,
                    "reason": det.reason,
                    "model": det.model_version.model_id if det.model_version else None,
                }
            ml["FLOW"] = {"status": "UPSTREAM_ONLY", "reason": "no flow features/model in v1"}
            out["ml"] = ml
            out["rules_current_enabled"] = RuleConfig.objects.filter(is_current=True, enabled=True).count()
            out["sources"] = {
                s.name: getattr(getattr(s, "health", None), "status", "NEVER_RUN")
                for s in Source.objects.all()
            }
            out["jobs_active"] = Job.objects.filter(
                status__in=["QUEUED", "RUNNING", "CANCEL_REQUESTED"]
            ).count()
        self.stdout.write(json.dumps(out, indent=2))
