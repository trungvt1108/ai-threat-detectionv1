from django.core.management.base import BaseCommand

from ai_threat_detection.worker.runner import run_worker


class Command(BaseCommand):
    help = "Run the local job worker in the foreground (Ctrl+C to stop). --once drains the queue and exits."

    def add_arguments(self, p):
        p.add_argument("--once", action="store_true")
        p.add_argument("--poll", type=float, default=1.0)
        p.add_argument("--max-runtime", type=float, default=None, help="seconds")

    def handle(self, *a, **o):
        try:
            n = run_worker(poll_s=o["poll"], once=o["once"], max_runtime_s=o["max_runtime"])
        except KeyboardInterrupt:
            self.stdout.write(
                "worker stopped; a job left RUNNING is recovered after its heartbeat goes stale"
            )
            return
        self.stdout.write(f"worker exit, jobs processed: {n}")
