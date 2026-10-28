from django.core.management.base import BaseCommand, CommandError

from ai_threat_detection.core.audit import audit
from ai_threat_detection.normalization.timeparse import validate_timezone
from ai_threat_detection.sources.adapters.registry import get_adapter
from ai_threat_detection.sources.models import PrivacyClass, Provenance, Source, SourceType
from ai_threat_detection.sources.paths import PathNotAllowedError, validate_source_root


class Command(BaseCommand):
    help = "Register a log source (root must be inside ATD_ALLOWED_SOURCE_ROOTS)."

    def add_arguments(self, p):
        p.add_argument("--name", required=True)
        p.add_argument("--type", required=True, choices=SourceType.values)
        p.add_argument("--root", required=True)
        p.add_argument(
            "--pattern", default="", help="file name glob (default: *.ndjson for JSON types, * for text)"
        )
        p.add_argument("--provenance", default=Provenance.USER_IMPORTED, choices=Provenance.values)
        p.add_argument("--privacy-class", default=PrivacyClass.PRIVATE, choices=PrivacyClass.values)
        p.add_argument(
            "--assume-timezone", default="", help="IANA zone for naive timestamps (explicit assumption)"
        )
        p.add_argument("--sensor", default="default")
        p.add_argument("--stable-id-field", default="")
        p.add_argument("--stale-after", type=int, default=900)
        p.add_argument("--expected-max-gap", type=int, default=None)
        p.add_argument("--license-note", default="")

    def handle(self, *a, **o):
        try:
            root = validate_source_root(o["root"])
        except PathNotAllowedError as exc:
            raise CommandError(str(exc))
        if o["assume_timezone"] and not validate_timezone(o["assume_timezone"]):
            raise CommandError("unknown timezone")
        src, created = Source.objects.update_or_create(
            name=o["name"],
            defaults=dict(
                source_type=o["type"],
                root_path=str(root),
                file_pattern=o["pattern"] or get_adapter(o["type"]).default_pattern,
                provenance=o["provenance"],
                privacy_class=o["privacy_class"],
                assume_timezone=o["assume_timezone"],
                sensor_name=o["sensor"][:64],
                stable_id_field=o["stable_id_field"],
                stale_after_seconds=o["stale_after"],
                expected_max_gap_seconds=o["expected_max_gap"],
                license_note=o["license_note"][:500],
            ),
        )
        if not created:
            src.config_version += 1
            src.save(update_fields=["config_version"])
        audit(
            "cli",
            "source.register" if created else "source.update",
            "source",
            src.name,
            "",
            type=src.source_type,
            provenance=src.provenance,
            privacy=src.privacy_class,
            tz=src.assume_timezone,
        )
        verb = "registered" if created else "updated"
        self.stdout.write(f"{verb} source {src.name} (config v{src.config_version})")
