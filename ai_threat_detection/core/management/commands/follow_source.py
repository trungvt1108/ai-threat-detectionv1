from ._common import JobCommand


class Command(JobCommand):
    help = "Follow a registered file for a bounded duration (rotation/truncation aware), detecting as data arrives."
    job_kind = "follow"
    timeout = 90000

    def add_arguments(self, p):
        p.add_argument("--source", required=True)
        p.add_argument("--file", required=True)
        p.add_argument(
            "--duration", type=float, default=60.0, help="seconds (bounded; no infinite background task)"
        )
        p.add_argument("--poll", type=float, default=1.0)
        self.add_job_args(p)

    def params(self, o):
        return {
            "source": o["source"],
            "file": o["file"],
            "duration_s": min(o["duration"], 86400),
            "poll_s": max(o["poll"], 0.2),
        }
