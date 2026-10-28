"""Job context passed into long-running operations: cooperative cancel, timeout, heartbeat."""

from __future__ import annotations

import time
from typing import Any


class JobCancelledError(Exception):
    pass


class JobTimeoutError(Exception):
    pass


class NullContext:
    """Used when a service is called directly (tests, synchronous helpers)."""

    job_id: int | None = None

    def __init__(self, timeout_s: float | None = None):
        self._deadline = (time.monotonic() + timeout_s) if timeout_s else None
        self.progress: dict[str, Any] = {}

    def check(self) -> None:
        if self._deadline and time.monotonic() > self._deadline:
            raise JobTimeoutError("timeout")

    def heartbeat(self, **progress: Any) -> None:
        self.progress.update(progress)
        self.check()

    def sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while True:
            self.check()
            remaining = end - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.25, remaining))
