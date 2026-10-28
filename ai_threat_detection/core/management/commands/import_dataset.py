from ._common import JobCommand


class Command(JobCommand):
    help = "Register a dataset manifest (hash-checked) and import each capture into its own ds:<id>/<capture> namespace."
    job_kind = "import_dataset"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--dataset", required=True)
        self.add_job_args(p)

    def params(self, o):
        return {"dataset": o["dataset"]}
