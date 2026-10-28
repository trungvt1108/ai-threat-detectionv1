from ._common import JobCommand


class Command(JobCommand):
    help = (
        "Generate a deterministic SYNTHETIC_DEMO dataset under .local/datasets/<id> (explicit demo opt-in)."
    )
    job_kind = "generate_synthetic"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--dataset-id", required=True)
        p.add_argument("--seed", type=int, default=1337)
        p.add_argument("--captures", type=int, default=10)
        self.add_job_args(p)

    def params(self, o):
        return {"dataset_id": o["dataset_id"], "seed": o["seed"], "n_captures": o["captures"]}
