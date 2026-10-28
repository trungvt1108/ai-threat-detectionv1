from ._common import JobCommand


class Command(JobCommand):
    help = "Batch-import one file of a registered source (chunked, idempotent), then run rules/ML detection."
    job_kind = "import"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--source", required=True)
        p.add_argument("--file", required=True, help="path relative to the source root")
        p.add_argument(
            "--from-start", action="store_true", help="ignore checkpoint (duplicates are still de-duplicated)"
        )
        p.add_argument("--no-detect", action="store_true")
        p.add_argument(
            "--close-all-windows", action="store_true", help="finalize: close windows up to the last event"
        )
        self.add_job_args(p)

    def params(self, o):
        return {
            "source": o["source"],
            "file": o["file"],
            "from_start": o["from_start"],
            "detect": not o["no_detect"],
            "finalize": o["close_all_windows"],
        }
