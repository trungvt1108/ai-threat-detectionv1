import json

from django.core.management.base import BaseCommand, CommandError

from ai_threat_detection.core.audit import audit
from ai_threat_detection.experiments.builder import InputSpec, build_dataset
from ai_threat_detection.experiments.datasets import DatasetError
from ai_threat_detection.sources.paths import PathNotAllowedError


class Command(BaseCommand):
    help = (
        "Package your own exported HTTP/AUTH logs (inside ATD_ALLOWED_SOURCE_ROOTS) into a dataset under "
        ".local/datasets/<id>, split into time-based captures with purge gaps. Then run import_dataset."
    )

    def add_arguments(self, p):
        p.add_argument("--dataset-id", required=True)
        p.add_argument("--http-file", action="append", default=[], help="repeatable")
        p.add_argument("--http-type", default="http_json", choices=["http_json", "http_combined"])
        p.add_argument("--auth-file", action="append", default=[], help="repeatable")
        p.add_argument("--auth-type", default="auth_json", choices=["auth_json", "auth_syslog"])
        p.add_argument(
            "--assume-timezone", default="", help="IANA zone for timestamps without offset (e.g. auth.log)"
        )
        p.add_argument("--capture-hours", type=float, default=24.0, help="capture length (default 1 day)")
        p.add_argument(
            "--gap-seconds",
            type=int,
            default=600,
            help="left out at the end of each capture; must be >= window size + lateness of the experiment",
        )
        p.add_argument("--labels", default="", help="optional JSON list of label intervals (see docs)")
        p.add_argument(
            "--assume-benign",
            action="store_true",
            help="record unlabeled background as BENIGN (your assertion) instead of UNKNOWN",
        )
        p.add_argument("--name", default="")
        p.add_argument("--description", default="")

    def handle(self, *a, **o):
        inputs = [InputSpec("HTTP", o["http_type"], f) for f in o["http_file"]] + [
            InputSpec("AUTH", o["auth_type"], f) for f in o["auth_file"]
        ]
        try:
            res = build_dataset(
                o["dataset_id"],
                inputs,
                assume_timezone=o["assume_timezone"],
                capture_hours=o["capture_hours"],
                gap_seconds=o["gap_seconds"],
                labels_path=o["labels"] or None,
                background="BENIGN" if o["assume_benign"] else "UNKNOWN",
                name=o["name"],
                description=o["description"],
            )
        except (DatasetError, PathNotAllowedError, ValueError, OSError) as exc:
            raise CommandError(str(exc)) from None
        audit("cli", "dataset.build", "dataset", res["dataset_id"], "", captures=res["captures"])
        self.stdout.write(json.dumps(res, indent=1))
        self.stdout.write(f"next: python manage.py import_dataset --dataset {res['dataset_id']}")
