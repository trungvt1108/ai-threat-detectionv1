from ._common import JobCommand


class Command(JobCommand):
    help = (
        "Build closed windows and run rules + ML (and upstream IDS grouping) for a namespace, "
        "or for every capture of an imported dataset (--dataset, all windows closed)."
    )
    job_kind = "detect"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--namespace", default="live")
        p.add_argument("--dataset", default="", help="run on every capture namespace ds:<dataset>/<capture>")
        p.add_argument("--close-all-windows", action="store_true")
        self.add_job_args(p)

    def params(self, o):
        if o["dataset"]:
            return {"dataset": o["dataset"], "finalize": True}
        return {"namespace": o["namespace"], "finalize": o["close_all_windows"]}
