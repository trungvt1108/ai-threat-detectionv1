"""LAB_OBSERVED capture: start the project fixture on loopback, drive scripted
harmless traffic against it, and package what the fixture logged as a dataset.

Safety rules enforced in code:
* The driver only talks to the fixture process started by this run
  (127.0.0.1 + the port it reported). No URL is accepted from users/UI.
* "Attacks" are wrong passwords against the fixture's fake accounts and GETs to
  a short list of non-existent paths; operational failure is a fault flag in the
  fixture. No scanning, exploit, or external traffic.
* Labels come from the driver's schedule (actual start/end wall-clock times) and
  are written to a sidecar; they never appear in the logged records.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ai_threat_detection.conf import REPO_ROOT, get_config
from ai_threat_detection.demo.synthetic import SLUG_RE

from .fixture_service import FIXTURE_ACCOUNTS

LAB_SCAN_PATHS = [
    "/.env",
    "/wp-login.php",
    "/admin",
    "/phpmyadmin/",
    "/.git/config",
    "/backup.zip",
    "/config.php",
    "/server-status",
    "/actuator/health",
    "/console",
    "/manager/html",
    "/test.php",
    "/xmlrpc.php",
    "/wp-admin/",
    "/db.sql",
    "/old/",
    "/solr/",
    "/jenkins/",
    "/owa/",
    "/remote/login",
    "/api/v1/debug",
    "/.svn/entries",
    "/cgi-bin/test.cgi",
    "/.aws/credentials",
    "/vendor/phpunit/",
]
NORMAL_PAGES = [
    ("/", 3),
    ("/products", 3),
    ("/products/{id}", 5),
    ("/static/app.css", 2),
    ("/static/app.js", 2),
    ("/api/items", 2),
    ("/api/items/{id}", 2),
    ("/cart", 1),
]

PROFILES: dict[str, dict[str, Any]] = {
    "default": {
        "capture_seconds": 45,
        "gap_seconds": 14,
        "normal_clients": 6,
        "window": {"size_s": 10, "stride_s": 10, "allowed_lateness_s": 2},
        "captures": [
            ("c00", []),
            ("c01", []),
            ("c02", []),
            ("c03", []),
            ("c04", [("auth_burst", 8, 15), ("http_scan", 25, 10), ("authorized_batch", 5, 15)]),
            ("c05", [("password_spray", 6, 15), ("ops_fault", 25, 12), ("log_degraded", 4, 8)]),
            ("c06", [("auth_burst_success", 6, 14), ("http_scan", 24, 10), ("ops_fault", 30, 10)]),
            (
                "c07",
                [
                    ("password_spray", 5, 14),
                    ("authorized_batch", 22, 12),
                    ("http_scan_small", 9, 10),
                    ("log_paused", 36, 6),
                ],
            ),
        ],
    },
    "smoke": {
        "capture_seconds": 6,
        "gap_seconds": 13,
        "normal_clients": 3,
        "window": {"size_s": 10, "stride_s": 10, "allowed_lateness_s": 2},
        "captures": [("c00", []), ("c01", [("auth_burst", 1, 4)]), ("c02", [("http_scan", 1, 4)])],
    },
}


class FixtureTarget:
    """A running fixture process. The only thing the driver may send requests to."""

    def __init__(self, log_dir: Path, seed: int):
        self.log_dir = log_dir
        self.ready = log_dir / ".fixture-ready.json"
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ai_threat_detection.lab.fixture_service",
                "--log-dir",
                str(log_dir),
                "--ready-file",
                str(self.ready),
                "--seed",
                str(seed),
            ],
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while not self.ready.exists():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.stop()
                raise RuntimeError("fixture service failed to start")
            time.sleep(0.05)
        info = json.loads(self.ready.read_text(encoding="utf-8"))
        self.port = int(info["port"])
        self._token = info["token"]
        self.base = f"http://127.0.0.1:{self.port}"

    def url(self, path: str) -> str:
        if not path.startswith("/") or path.startswith("//") or "://" in path or "\\" in path:
            raise ValueError("driver only accepts fixture-relative paths")
        full = self.base + path
        parts = urllib.parse.urlsplit(full)
        if parts.hostname != "127.0.0.1" or full.split("/", 3)[2] != self.base.split("/", 3)[2]:
            raise ValueError("driver target must be the fixture started by this run")
        return full

    def control(self, **flags: bool) -> None:
        req = urllib.request.Request(  # noqa: S310 - fixture URL
            self.url("/__fixture/control"),
            data=json.dumps(flags).encode(),
            method="POST",
            headers={"X-Fixture-Control-Token": self._token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 - URL built by FixtureTarget.url (loopback only)
            r.read()

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        try:
            self.ready.unlink()
        except FileNotFoundError:
            pass


class Driver:
    def __init__(self, target: FixtureTarget, seed: int):
        self.t = target
        self.rng = random.Random(seed)
        self.lock = threading.Lock()
        self.requests = 0

    def call(
        self, client: str, method: str, path: str, body: dict | None = None, cookie: str | None = None
    ) -> int:
        headers = {"X-Lab-Client": client}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        req = urllib.request.Request(self.t.url(path), data=data, method=method, headers=headers)  # noqa: S310 - fixture URL
        with self.lock:
            self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 - URL built by FixtureTarget.url (loopback only)
                r.read()
                return r.status
        except urllib.error.HTTPError as e:
            e.read()
            return e.code
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            return 0


def _normal_client(drv: Driver, name: str, stop: threading.Event, seed: int) -> None:
    rng = random.Random(seed)
    user = list(FIXTURE_ACCOUNTS)[seed % len(FIXTURE_ACCOUNTS)]
    pages = [p for p, w in NORMAL_PAGES for _ in range(w)]
    next_login = time.monotonic() + rng.uniform(1, 8)
    rate = rng.uniform(1.2, 2.5)
    while not stop.is_set():
        if time.monotonic() >= next_login:
            if rng.random() < 0.15:
                drv.call(
                    name, "POST", "/login", {"username": user, "password": "typo-" + str(rng.randint(0, 99))}
                )
            drv.call(name, "POST", "/login", {"username": user, "password": FIXTURE_ACCOUNTS[user]})
            next_login = time.monotonic() + rng.uniform(8, 16)
        else:
            p = rng.choice(pages).replace("{id}", str(rng.randint(1, 400)))
            cookie = f"session=lab{rng.randint(10**8, 10**9)}" if rng.random() < 0.05 else None
            drv.call(name, "GET", p, cookie=cookie)
        stop.wait(rng.expovariate(rate))


def _scenario(drv: Driver, name: str, dur: float, stop: threading.Event, client: str) -> None:
    rng = drv.rng
    end = time.monotonic() + dur
    users = list(FIXTURE_ACCOUNTS)
    if name == "ops_fault":
        drv.t.control(fault=True)
        stop.wait(dur)
        drv.t.control(fault=False)
        return
    if name in ("log_degraded", "log_paused"):
        drv.t.control(**{name: True})
        stop.wait(dur)
        drv.t.control(**{name: False})
        return
    while time.monotonic() < end and not stop.is_set():
        if name in ("auth_burst", "auth_burst_success"):
            drv.call(
                client,
                "POST",
                "/login",
                {"username": rng.choice(users[:2] + ["admin"]), "password": f"guess{rng.randint(0, 9999)}"},
            )
            stop.wait(rng.uniform(0.2, 0.45))
        elif name == "password_spray":
            u = rng.choice(users + ["lab-ghost-1", "lab-ghost-2", "lab-ghost-3"])
            drv.call(client, "POST", "/login", {"username": u, "password": "Spring2026-guess"})
            stop.wait(rng.uniform(0.4, 0.8))
        elif name in ("http_scan", "http_scan_small"):
            drv.call(client, "GET", rng.choice(LAB_SCAN_PATHS))
            stop.wait(rng.uniform(0.08, 0.15) if name == "http_scan" else rng.uniform(0.4, 0.6))
        elif name == "authorized_batch":
            drv.call(client, "GET", f"/api/export/{rng.randint(1, 9999)}")
            stop.wait(rng.uniform(0.07, 0.12))
    if name == "auth_burst_success" and not stop.is_set():
        u = users[2]
        for _ in range(3):
            drv.call(client, "POST", "/login", {"username": u, "password": "guess-final"})
        drv.call(client, "POST", "/login", {"username": u, "password": FIXTURE_ACCOUNTS[u]})


LABEL_OF = {
    "auth_burst": ("SUSPICIOUS_PATTERN", "AUTH"),
    "auth_burst_success": ("SUSPICIOUS_PATTERN", "AUTH"),
    "password_spray": ("SUSPICIOUS_PATTERN", "AUTH"),
    "http_scan": ("SUSPICIOUS_PATTERN", "HTTP"),
    "http_scan_small": ("SUSPICIOUS_PATTERN", "HTTP"),
    "authorized_batch": ("AUTHORIZED_LOAD", "HTTP"),
    "ops_fault": ("OPERATIONAL_ANOMALY", "HTTP"),
}


def _run_capture(cdir: Path, cid: str, plan: list, prof: dict, seed: int, ctx) -> dict[str, Any]:
    target = FixtureTarget(cdir, seed)
    drv = Driver(target, seed)
    stop = threading.Event()
    intervals: list[dict[str, Any]] = []
    toggles: list[dict[str, Any]] = []
    threads = []
    t_start = datetime.now(UTC)
    try:
        for k in range(prof["normal_clients"]):
            th = threading.Thread(
                target=_normal_client, args=(drv, f"lab-client-{k + 1}", stop, seed * 100 + k), daemon=True
            )
            th.start()
            threads.append(th)

        def run_sc(idx: int, name: str, offset: float, dur: float) -> None:
            if stop.wait(offset):
                return
            client = {"authorized_batch": "lab-batch-job"}.get(name, f"lab-attacker-{seed % 50 + idx + 1}")
            s = datetime.now(UTC)
            _scenario(drv, name, dur, stop, client)
            e = datetime.now(UTC) + timedelta(seconds=1)
            if name in LABEL_OF:
                label, dom = LABEL_OF[name]
                entity: Any = "*" if name == "ops_fault" else {"kind": "ip", "value": client}
                intervals.append(
                    {
                        "label": label,
                        "scenario": name,
                        "instance": f"{cid}-{name}-{idx}",
                        "domain": dom,
                        "entity": entity,
                        "start": s.isoformat(),
                        "end": e.isoformat(),
                    }
                )
            else:
                toggles.append({"data_quality": name, "start": s.isoformat(), "end": e.isoformat()})

        for idx, (name, offset, dur) in enumerate(plan):
            th = threading.Thread(target=run_sc, args=(idx, name, offset, dur), daemon=True)
            th.start()
            threads.append(th)
        end = time.monotonic() + prof["capture_seconds"]
        while time.monotonic() < end:
            if ctx is not None:
                ctx.heartbeat(capture=cid, requests=drv.requests)
            time.sleep(0.5)
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=10)
        target.stop()
    t_end = datetime.now(UTC)
    labels = {
        "capture_id": cid,
        "label_source": "lab driver schedule (actual start/end wall-clock); background = scripted normal clients",
        "background_label": "BENIGN",
        "intervals": intervals,
        "data_quality_toggles": toggles,
    }
    (cdir / "labels.json").write_text(json.dumps(labels, indent=1), encoding="utf-8")
    return {"capture_id": cid, "start": t_start, "end": t_end, "requests": drv.requests, "plan": plan}


def run_lab_capture(dataset_id: str, profile: str = "default", seed: int = 7, ctx=None) -> dict[str, Any]:
    if not SLUG_RE.match(dataset_id):
        raise ValueError("dataset_id must be a lowercase slug")
    prof = PROFILES[profile]
    root = get_config().datasets_dir / dataset_id
    if root.exists():
        raise FileExistsError("dataset directory exists; choose a new id")
    (root / "captures").mkdir(parents=True)
    metas = []
    for i, (cid, plan) in enumerate(prof["captures"]):
        if i:
            time.sleep(prof["gap_seconds"])  # purge gap between captures (> window + lateness)
        cdir = root / "captures" / cid
        cdir.mkdir()
        m = _run_capture(cdir, cid, plan, prof, seed + i, ctx)
        for f in ("http.ndjson", "auth.ndjson"):
            (cdir / f).touch(exist_ok=True)
        metas.append(m)
    manifest = {
        "manifest_version": "atd.dataset.v1",
        "dataset_id": dataset_id,
        "name": f"Lab observation {dataset_id} ({profile})",
        "provenance": "LAB_OBSERVED",
        "privacy_class": "LAB",
        "license": "Produced locally by this project's fixture; no third-party data",
        "usage_constraints": "Local lab only. Client identities are driver-assigned labels (X-Lab-Client) over loopback.",
        "description": "Logs written by the project fixture service while a scripted driver sent harmless requests.",
        "generator": {
            "module": "ai_threat_detection.lab.capture",
            "profile": profile,
            "seed": seed,
            "recommended_window": prof["window"],
            "note": "real wall-clock timestamps from the fixture; short captures and windows (lab scale)",
        },
        "label_definition": {
            "unit": "entity-window overlap with labeled interval of the same entity ('*' = all entities of the domain)",
            "labels": {
                "SUSPICIOUS_PATTERN": "scripted wrong-password bursts/spraying on fake accounts; unknown-path GET bursts",
                "OPERATIONAL_ANOMALY": "fixture fault mode (503 + latency)",
                "AUTHORIZED_LOAD": "scripted permitted export batch",
                "BENIGN": "scripted normal clients",
            },
        },
        "captures": [
            {
                "capture_id": m["capture_id"],
                "scenario_group": m["capture_id"],
                "start": m["start"].isoformat(),
                "end": m["end"].isoformat(),
                "files": {
                    "HTTP": f"captures/{m['capture_id']}/http.ndjson",
                    "AUTH": f"captures/{m['capture_id']}/auth.ndjson",
                },
                "labels": f"captures/{m['capture_id']}/labels.json",
                "description": "baseline (normal only)"
                if not m["plan"]
                else "scenarios: " + ", ".join(p[0] for p in m["plan"]),
            }
            for m in metas
        ],
    }
    (root / "dataset.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "dataset_id": dataset_id,
        "captures": len(metas),
        "requests": sum(m["requests"] for m in metas),
        "window_recommended": prof["window"],
    }
