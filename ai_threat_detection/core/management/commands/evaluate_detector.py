from ._common import JobCommand


class Command(JobCommand):
    help = "Frozen evaluation on the experiment test split (rules-only / ML-only / hybrid)."
    job_kind = "evaluate"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--experiment", required=True)
        p.add_argument("--domain", required=True, choices=["AUTH", "HTTP"])
        p.add_argument("--model", required=True)
        p.add_argument("--rerun-reason", default="", help="required if the test split was already evaluated")
        self.add_job_args(p)

    def params(self, o):
        return {
            "experiment": o["experiment"],
            "domain": o["domain"],
            "model_id": o["model"],
            "rerun_reason": o["rerun_reason"],
        }
