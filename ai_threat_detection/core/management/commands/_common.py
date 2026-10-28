"""Shared helpers for management commands: run through the job queue (inline by
default, ``--enqueue`` to hand off to ``runworker``) and print a JSON summary."""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError


class JobCommand(BaseCommand):
    job_kind = ""
    timeout = 3600

    def add_job_args(self, parser) -> None:
        parser.add_argument(
            "--enqueue", action="store_true", help="queue for runworker instead of running inline"
        )
        parser.add_argument("--timeout", type=int, default=self.timeout)

    def params(self, opts) -> dict:  # pragma: no cover - overridden
        return {}

    def handle(self, *args, **opts):
        from ai_threat_detection.worker.runner import enqueue, run_inline

        params = self.params(opts)
        if opts.get("enqueue"):
            job = enqueue(self.job_kind, params, actor="cli", timeout_seconds=opts["timeout"])
            self.stdout.write(json.dumps({"job": job.pk, "status": job.status}))
            return
        job = run_inline(self.job_kind, params, actor="cli", timeout_seconds=opts["timeout"])
        self.stdout.write(
            json.dumps(
                {"job": job.pk, "status": job.status, "error": job.error, "result": job.result},
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        )
        if job.status != "SUCCEEDED":
            raise CommandError(f"job {job.pk} {job.status}: {job.error}")
