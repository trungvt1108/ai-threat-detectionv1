import json

from django.core.management.base import BaseCommand, CommandError

from ai_threat_detection.conf import REPO_ROOT, get_config
from ai_threat_detection.publishing.publish_check import publish_check


class Command(BaseCommand):
    help = "Read-only publication gate over Git-visible files (and optionally public drafts)."

    def add_arguments(self, p):
        p.add_argument("--include-drafts", action="store_true")
        p.add_argument("--json", action="store_true")

    def handle(self, *a, **o):
        cfg = get_config()
        res = publish_check(
            REPO_ROOT, o["include_drafts"], cfg.public_drafts_dir, cfg.public_identity_allowlist
        )
        if o["json"]:
            self.stdout.write(json.dumps(res, indent=2))
        else:
            self.stdout.write(
                f"result: {res['result']}  summary: {res['summary']}  allowlisted: {res['allowlisted_findings']}"
            )
            self.stdout.write(f"scope: {res['scope']}")
            self.stdout.write(f"gitleaks: {res['gitleaks']}")
            self.stdout.write(f"staged files: {len(res['staged_files'])}")
            for f in res["findings"][:200]:
                self.stdout.write(f"  [{f['severity']}] {f['kind']} {f['path']}:{f['line']} {f['excerpt']}")
            self.stdout.write(res["note"])
        if res["result"] == "FAIL":
            raise CommandError("publish_check FAIL")
