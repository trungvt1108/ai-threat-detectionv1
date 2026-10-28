from ._common import JobCommand


class Command(JobCommand):
    help = "Run the loopback fixture service + scripted harmless driver and package its logs as a LAB_OBSERVED dataset."
    job_kind = "lab_capture"
    timeout = 1800

    def add_arguments(self, p):
        p.add_argument("--dataset-id", required=True)
        p.add_argument("--profile", default="default", choices=["default", "smoke"])
        self.add_job_args(p)

    def params(self, o):
        return {"dataset_id": o["dataset_id"], "profile": o["profile"]}
