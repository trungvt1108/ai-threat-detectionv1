"""Project-managed fixture web service for LAB_OBSERVED captures.

A small real HTTP server (stdlib) bound to loopback only. It serves a toy shop
API, a login endpoint backed by FAKE fixture accounts, and writes its own access
and auth logs as NDJSON - i.e. the logs are what the service actually observed.

Deliberately "careless" logging: it records a Cookie header when present, so the
importer's redaction is exercised on real emitted logs.

Control endpoint (token from the run directory) toggles:
* fault: 503 responses with probability + added latency (operational failure)
* log_degraded: some records without timestamp/status (data-quality scenario)
* log_paused: stop writing logs (source gap)

Run: python -m ai_threat_detection.lab.fixture_service --log-dir DIR --ready-file FILE
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import secrets
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Fixture-only demo accounts. Not secrets; they exist only inside this toy service.
FIXTURE_ACCOUNTS = {
    "lab-alice": "fixture-only-alice",
    "lab-bob": "fixture-only-bob",
    "lab-carol": "fixture-only-carol",
    "lab-dave": "fixture-only-dave",
    "lab-erin": "fixture-only-erin",
    "lab-frank": "fixture-only-frank",
}
CLIENT_RE = re.compile(r"^lab-[a-z0-9-]{1,32}$")
LOOPBACK = {"127.0.0.1", "::1"}
MAX_BODY = 4096


class State:
    def __init__(self, log_dir: Path, token: str, seed: int):
        self.lock = threading.Lock()
        self.fault = False
        self.fault_p = 0.6
        self.fault_latency_ms = 250
        self.log_degraded = False
        self.log_paused = False
        self.token = token
        self.rng = random.Random(seed)
        self.http_log = open(log_dir / "http.ndjson", "a", encoding="utf-8", buffering=1)
        self.auth_log = open(log_dir / "auth.ndjson", "a", encoding="utf-8", buffering=1)

    def write(self, fh, rec: dict) -> None:
        with self.lock:
            if self.log_paused:
                return
            if self.log_degraded:
                r = self.rng.random()
                if r < 0.25:
                    rec.pop("timestamp", None)
                elif r < 0.45:
                    rec["timestamp"] = rec["timestamp"][:19]  # naive timestamp (no offset)
                elif r < 0.6:
                    rec.pop("status", None)
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class Handler(BaseHTTPRequestHandler):
    server_version = "atd-fixture/1.0"
    state: State

    def log_message(self, format, *args):  # noqa: A002 - silence default stderr access log
        return

    def _client(self) -> str:
        h = self.headers.get("X-Lab-Client", "")
        return h if CLIENT_RE.match(h) else self.client_address[0]

    def _send(self, status: int, body: bytes, ctype: str = "application/json") -> int:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        return len(body)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return b""
        return self.rfile.read(n) if n > 0 else b""

    def _handle(self) -> None:
        t0 = time.perf_counter()
        st = self.state
        path = self.path
        route = path.split("?", 1)[0]
        status, body, auth_rec = 200, b"{}", None
        if route == "/__fixture/control" and self.command == "POST":
            if not secrets.compare_digest(self.headers.get("X-Fixture-Control-Token", ""), st.token):
                status, body = 403, b'{"error":"forbidden"}'
            else:
                cmd = json.loads(self._read_body() or b"{}")
                with st.lock:
                    for k in ("fault", "log_degraded", "log_paused"):
                        if k in cmd:
                            setattr(st, k, bool(cmd[k]))
                status, body = 200, b'{"ok":true}'
            self._send(status, body)
            return  # control calls are not part of observed traffic
        if st.fault and route != "/health" and st.rng.random() < st.fault_p:
            time.sleep(st.fault_latency_ms / 1000.0)
            status, body = 503, b'{"error":"upstream unavailable"}'
        elif route == "/health":
            body = b'{"ok":true}'
        elif route == "/login" and self.command == "POST":
            raw = self._read_body()
            try:
                data = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                data = {}
            user = str(data.get("username", ""))[:64]
            ok = FIXTURE_ACCOUNTS.get(user) is not None and secrets.compare_digest(
                FIXTURE_ACCOUNTS.get(user, ""), str(data.get("password", ""))
            )
            status = 200 if ok else 401
            body = b'{"login":"ok"}' if ok else b'{"login":"failed"}'
            auth_rec = {
                "timestamp": _now(),
                "host": "lab-fixture",
                "service": "fixture-login",
                "src_ip": self._client(),
                "user": user or None,
                "outcome": "success" if ok else "failure",
                "auth_method": "password",
                "reason": None
                if ok
                else ("unknown_user" if user not in FIXTURE_ACCOUNTS else "invalid_password"),
            }
        elif route in ("/", "/products", "/cart"):
            body = json.dumps({"page": route, "items": list(range(20))}).encode()
        elif re.fullmatch(r"/products/\d{1,6}", route):
            pid = int(route.rsplit("/", 1)[1])
            status = 404 if pid % 37 == 0 else 200
            body = (
                b'{"error":"not found"}'
                if status == 404
                else json.dumps({"id": pid, "name": "item"}).encode()
            )
        elif route in ("/api/items",) or re.fullmatch(r"/api/items/\d{1,6}", route):
            body = json.dumps({"items": [{"id": i} for i in range(10)]}).encode()
        elif re.fullmatch(r"/api/export/\d{1,6}", route):
            body = json.dumps({"rows": ["x" * 40] * 200}).encode()
        elif route in ("/static/app.css", "/static/app.js"):
            body = b"/* static */" + b" " * 4000
        else:
            status, body = 404, b'{"error":"not found"}'
        sent = self._send(status, body)
        dur = (time.perf_counter() - t0) * 1000.0
        rec = {
            "timestamp": _now(),
            "sensor": "lab-fixture",
            "client_id": self._client(),
            "method": self.command,
            "path": path[:512],
            "status": status,
            "bytes": sent,
            "duration_ms": round(dur, 3),
        }
        cookie = self.headers.get("Cookie")
        if cookie:
            rec["request_headers"] = {
                "cookie": cookie[:200]
            }  # careless logging on purpose; importer must drop it
        st.write(st.http_log, rec)
        if auth_rec is not None:
            st.write(st.auth_log, auth_rec)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle


def serve(
    log_dir: Path,
    ready_file: Path,
    host: str = "127.0.0.1",
    port: int = 0,
    seed: int = 0,
    allow_container_bind: bool = False,
):
    if host not in LOOPBACK and not allow_container_bind:
        raise SystemExit("fixture refuses to bind to a non-loopback address")
    log_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(16)
    state = State(log_dir, token, seed)
    Handler.state = state
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    tmp = ready_file.with_suffix(".tmp")
    tmp.write_text(
        json.dumps({"port": httpd.server_address[1], "token": token, "pid": os.getpid()}), encoding="utf-8"
    )
    os.replace(tmp, ready_file)
    try:
        httpd.serve_forever(poll_interval=0.2)
    finally:
        state.http_log.close()
        state.auth_log.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--log-dir", required=True)
    ap.add_argument("--ready-file", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument(
        "--container", action="store_true", help="allow 0.0.0.0 inside an isolated container only"
    )
    a = ap.parse_args()
    serve(Path(a.log_dir), Path(a.ready_file), a.host, a.port, a.seed, allow_container_bind=a.container)


if __name__ == "__main__":
    main()
