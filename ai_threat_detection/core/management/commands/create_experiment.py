from ._common import JobCommand


class Command(JobCommand):
    help = "Create an immutable experiment: chronological group split + purge gap + windows + labels + split manifest."
    job_kind = "create_experiment"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--dataset", required=True)
        p.add_argument("--exp-id", required=True)
        p.add_argument("--name", default="")
        p.add_argument("--window-size", type=int, default=300)
        p.add_argument("--stride", type=int, default=None)
        p.add_argument("--lateness", type=int, default=60)
        p.add_argument("--min-events", type=int, default=1)
        p.add_argument("--counts", default="", help="train,val,test capture-group counts, e.g. 5,2,3")
        p.add_argument("--random-state", type=int, default=20260101)
        p.add_argument(
            "--http-feature-set",
            default="http_v1",
            choices=["http_v1", "http_v1_core"],
            help="http_v1_core for HTTP logs without response size/duration (e.g. plain combined logs)",
        )
        self.add_job_args(p)

    def params(self, o):
        return {
            "dataset": o["dataset"],
            "exp_id": o["exp_id"],
            "name": o["name"] or o["exp_id"],
            "window": {
                "size_s": o["window_size"],
                "stride_s": o["stride"] or o["window_size"],
                "allowed_lateness_s": o["lateness"],
                "min_events": o["min_events"],
            },
            "counts": [int(x) for x in o["counts"].split(",")] if o["counts"] else None,
            "random_state": o["random_state"],
            "feature_sets": {"AUTH": "auth_v1", "HTTP": o["http_feature_set"]},
        }
