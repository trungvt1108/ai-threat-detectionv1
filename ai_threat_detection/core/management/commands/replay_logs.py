from ._common import JobCommand


class Command(JobCommand):
    help = "Replay a source file in timestamp order into a separate replay:<name> namespace with incremental detection."
    job_kind = "replay"
    timeout = 3600

    def add_arguments(self, p):
        p.add_argument("--source", required=True)
        p.add_argument("--file", required=True)
        p.add_argument("--namespace", default="", help="replay:<name> (default replay:job<id>)")
        p.add_argument(
            "--speed", type=float, default=0.0, help="0 = as fast as possible; N = N x event-time speed"
        )
        p.add_argument("--chunk-size", type=int, default=200)
        self.add_job_args(p)

    def params(self, o):
        return {
            "source": o["source"],
            "file": o["file"],
            "namespace": (
                o["namespace"]
                if not o["namespace"] or o["namespace"].startswith("replay:")
                else "replay:" + o["namespace"]
            ),
            "speed": o["speed"],
            "chunk_size": o["chunk_size"],
        }
