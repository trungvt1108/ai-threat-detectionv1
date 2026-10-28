from ._common import JobCommand


class Command(JobCommand):
    help = "Train an IsolationForest candidate for one domain of an experiment (never auto-activates)."
    job_kind = "train"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--experiment", required=True)
        p.add_argument("--domain", required=True, choices=["AUTH", "HTTP"])
        p.add_argument(
            "--train-on-unknown",
            action="store_true",
            help="also use UNKNOWN-label train windows as baseline (contamination risk recorded)",
        )
        self.add_job_args(p)

    def params(self, o):
        return {
            "experiment": o["experiment"],
            "domain": o["domain"],
            "train_on_unknown": o["train_on_unknown"],
        }
