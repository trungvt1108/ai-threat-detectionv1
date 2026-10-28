from ._common import JobCommand


class Command(JobCommand):
    help = "Export a Markdown/HTML/JSON report (experiment or alerts). --public-draft writes a reduced draft for review."
    job_kind = "report"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--experiment", default="")
        p.add_argument("--namespace", default="live")
        p.add_argument("--days", type=int, default=30)
        p.add_argument("--public-draft", action="store_true")
        self.add_job_args(p)

    def params(self, o):
        return {
            "public_draft": o["public_draft"],
            "namespace": o["namespace"],
            "days": o["days"],
            **({"experiment": o["experiment"]} if o["experiment"] else {}),
        }
