"""Deterministic synthetic dataset generator (provenance SYNTHETIC_DEMO).

Produces raw HTTP and auth NDJSON as a careless application might log them
(including fake cookies/tokens/passwords that the importer must strip), plus a
label sidecar per capture derived from the controlled schedule. All identities
are documentation-range IPs (RFC 5737) and fake user names. Nothing here is
real traffic; metrics computed on it only describe behavior on this generator.

Capture plan: the first half are baseline captures (normal activity only, still
with typos, broken links, rare 5xx and data-quality noise); later captures add
scenario instances: auth bursts, password spraying, low-and-slow guessing,
unknown-path bursts, an operational outage (5xx + latency) and an authorized
batch job (high but legitimate load).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np

from ai_threat_detection.conf import get_config

GEN_VERSION = "synthetic-gen-1.0.0"
BASE = datetime(2026, 3, 2, 8, 0, tzinfo=UTC)
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")

CLIENTS = [f"198.51.100.{i}" for i in range(10, 50)]
USERS = [f"user{i:03d}" for i in range(1, 31)]
BATCH_HOST = "192.0.2.250"
SCAN_PATHS = [
    "/.env",
    "/wp-login.php",
    "/admin",
    "/admin/login",
    "/phpmyadmin/",
    "/.git/config",
    "/backup.zip",
    "/config.php",
    "/server-status",
    "/actuator/health",
    "/actuator/env",
    "/vendor/phpunit/",
    "/cgi-bin/test.cgi",
    "/.aws/credentials",
    "/api/v1/debug",
    "/console",
    "/manager/html",
    "/old/",
    "/test.php",
    "/xmlrpc.php",
    "/wp-admin/",
    "/.DS_Store",
    "/db.sql",
    "/robots.txt",
    "/sitemap.xml",
    "/solr/",
    "/jenkins/",
    "/.svn/entries",
    "/owa/",
    "/remote/login",
]
BROWSER_PATHS = [
    ("/", 0.15),
    ("/products", 0.15),
    ("/products/{id}", 0.25),
    ("/static/app.js", 0.1),
    ("/static/app.css", 0.1),
    ("/search?q={q}", 0.08),
    ("/account", 0.07),
    ("/login", 0.05),
    ("/cart", 0.05),
]
API_PATHS = [
    ("/api/items?page={n}", 0.4),
    ("/api/items/{id}", 0.3),
    ("/api/orders", 0.15),
    ("/api/session", 0.15),
]
PLANS = [
    ["auth_burst", "http_scan", "authorized_batch"],
    ["password_spray", "ops_outage", "low_and_slow"],
    ["auth_burst_success", "http_scan", "ops_outage"],
    ["password_spray", "authorized_batch", "low_and_slow", "http_scan_small"],
    ["auth_burst", "ops_outage", "authorized_batch", "http_scan"],
]


def _iso(t: datetime, rng: np.random.Generator) -> str:
    ms = t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}"
    return ms + ("Z" if rng.random() < 0.7 else "+00:00")


class _Capture:
    def __init__(self, seed: int, idx: int, start: datetime, hours: float):
        self.rng = np.random.default_rng([seed, idx])
        self.start = start
        self.end = start + timedelta(hours=hours)
        self.http: list[tuple[datetime, dict[str, Any]]] = []
        self.auth: list[tuple[datetime, dict[str, Any]]] = []
        self.intervals: list[dict[str, Any]] = []

    def t_at(self, seconds: float) -> datetime:
        return self.start + timedelta(seconds=float(seconds))

    def label(
        self, label: str, scenario: str, domain: str, entity: Any, s: datetime, e: datetime, inst: str
    ) -> None:
        self.intervals.append(
            {
                "label": label,
                "scenario": scenario,
                "instance": inst,
                "domain": domain,
                "entity": entity if entity == "*" else {"kind": "ip", "value": entity},
                "start": s.isoformat(),
                "end": e.isoformat(),
            }
        )


def _population(seed: int) -> list[dict[str, Any]]:
    rng = np.random.default_rng([seed, 999])
    pop = []
    for ip in CLIENTS:
        pop.append(
            {
                "ip": ip,
                "rate": float(np.clip(rng.lognormal(np.log(2.0), 0.5), 0.3, 8.0)),
                "p_active": float(rng.uniform(0.2, 0.7)),
                "profile": "api" if rng.random() < 0.25 else "browser",
            }
        )
    return pop


def _http_request(cap: _Capture, t: datetime, ip: str, profile: str) -> dict[str, Any]:
    rng = cap.rng
    paths = BROWSER_PATHS if profile == "browser" else API_PATHS
    p = np.array([w for _, w in paths])
    tmpl = paths[int(rng.choice(len(paths), p=p / p.sum()))][0]
    path = tmpl.replace("{id}", str(int(rng.integers(1, 5000)))).replace("{n}", str(int(rng.integers(1, 40))))
    path = path.replace("{q}", "shoes" if rng.random() < 0.5 else "bag")
    method = "GET"
    if tmpl in ("/login", "/api/orders"):
        method = "POST"
    elif tmpl == "/api/session":
        method = str(rng.choice(["GET", "POST", "DELETE"], p=[0.4, 0.5, 0.1]))
    elif rng.random() < 0.01:
        method = "PUT"
    status = 200
    if tmpl.startswith("/static") and rng.random() < 0.3:
        status = 304
    if tmpl == "/products/{id}" and rng.random() < 0.03:
        status = 404
    if tmpl == "/account" and rng.random() < 0.02:
        status = 401
    if rng.random() < 0.002:
        status = 500
    if status == 304:
        nbytes = 0
    elif status >= 400:
        nbytes = int(rng.integers(150, 600))
    elif tmpl.startswith("/static"):
        nbytes = int(rng.lognormal(np.log(20000), 0.3))
    elif tmpl.startswith("/api"):
        nbytes = int(rng.lognormal(np.log(1500), 0.6))
    else:
        nbytes = int(rng.lognormal(np.log(8000), 0.4))
    base = 4.0 if tmpl.startswith("/static") else (25.0 if tmpl.startswith("/api") else 35.0)
    lat = float(rng.lognormal(np.log(base), 0.5)) * (10.0 if rng.random() < 0.01 else 1.0)
    rec: dict[str, Any] = {
        "timestamp": _iso(t, rng),
        "sensor": "web-01",
        "client_ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "bytes": nbytes,
        "duration_ms": round(lat, 2),
        "user_agent": "Mozilla/5.0 (synthetic)" if profile == "browser" else "synthetic-api-client/1.0",
    }
    r = rng.random()
    if r < 0.03:
        rec["headers"] = {
            "cookie": f"session={rng.integers(10**12, 10**13)}",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGlj",
        }
    elif r < 0.04:
        rec["path"] = f"/reset?token={rng.integers(10**15, 10**16):x}&user=someone@example.com"
    return rec


def _normal_http(cap: _Capture, pop: list[dict[str, Any]], outage_gap: tuple[float, float] | None) -> None:
    rng = cap.rng
    total_s = (cap.end - cap.start).total_seconds()
    n_blocks = int(total_s // 300)
    for b in range(n_blocks):
        f = 0.7 + 0.6 * np.sin(np.pi * b / max(n_blocks, 1))
        for c in pop:
            if rng.random() > c["p_active"]:
                continue
            n = int(rng.poisson(c["rate"] * 5 * f))
            for _ in range(n):
                sec = b * 300 + float(rng.uniform(0, 300))
                if outage_gap and outage_gap[0] <= sec < outage_gap[1]:
                    continue  # logging outage: events lost
                t = cap.t_at(sec)
                cap.http.append((t, _http_request(cap, t, c["ip"], c["profile"])))


def _auth_rec(
    cap: _Capture,
    t: datetime,
    ip: str,
    user: str,
    ok: bool,
    service: str = "webapp",
    reason: str | None = None,
):
    rec: dict[str, Any] = {
        "timestamp": _iso(t, cap.rng),
        "host": "auth-01",
        "service": service,
        "src_ip": ip,
        "user": user,
        "outcome": "success" if ok else "failure",
        "auth_method": "password",
    }
    if reason:
        rec["reason"] = reason
    if cap.rng.random() < 0.01:
        rec["password"] = "fake-password-should-be-dropped"  # noqa: S105 - synthetic careless-logger field; must be dropped
    return rec


def _normal_auth(cap: _Capture, home: dict[str, str]) -> None:
    rng = cap.rng
    total_s = (cap.end - cap.start).total_seconds()
    for u in USERS:
        for _ in range(int(rng.poisson(3 * total_s / (4 * 3600)))):
            sec = float(rng.uniform(0, total_s - 120))
            ip = home[u]
            service = str(rng.choice(["webapp", "vpn", "sshd"], p=[0.8, 0.15, 0.05]))
            if rng.random() < 0.12:
                for k in range(int(rng.integers(1, 3))):
                    t = cap.t_at(sec + k * float(rng.uniform(3, 15)))
                    cap.auth.append((t, _auth_rec(cap, t, ip, u, False, service, "invalid_password")))
                sec += 40
            t = cap.t_at(sec)
            cap.auth.append((t, _auth_rec(cap, t, ip, u, True, service)))
    for _ in range(int(rng.poisson(2))):
        t = cap.t_at(float(rng.uniform(0, total_s)))
        cap.auth.append(
            (t, _auth_rec(cap, t, str(rng.choice(CLIENTS)), "olduser", False, "webapp", "unknown_user"))
        )


def _attacker(rng: np.random.Generator) -> str:
    return f"203.0.113.{int(rng.integers(10, 250))}"


def _scenario(cap: _Capture, name: str, inst: str) -> None:
    rng = cap.rng
    total_s = (cap.end - cap.start).total_seconds()
    t0s = float(rng.uniform(600, total_s - 2400))
    t0 = cap.t_at(t0s)
    if name in ("auth_burst", "auth_burst_success"):
        ip = _attacker(rng)
        targets = list(rng.choice(USERS + ["admin", "root"], size=int(rng.integers(1, 4)), replace=False))
        dur = float(rng.uniform(240, 600))
        s = 0.0
        while s < dur:
            t = cap.t_at(t0s + s)
            cap.auth.append(
                (t, _auth_rec(cap, t, ip, str(rng.choice(targets)), False, "webapp", "invalid_password"))
            )
            s += float(rng.uniform(3, 12))
        end = cap.t_at(t0s + s)
        if name == "auth_burst_success":
            u = str(targets[0])
            for k in range(3):
                t = cap.t_at(t0s + s + k * 4)
                cap.auth.append((t, _auth_rec(cap, t, ip, u, False, "webapp", "invalid_password")))
            end = cap.t_at(t0s + s + 16)
            cap.auth.append((end, _auth_rec(cap, end, ip, u, True, "webapp")))
        cap.label("SUSPICIOUS_PATTERN", name, "AUTH", ip, t0, end + timedelta(seconds=1), inst)
    elif name == "password_spray":
        ip = _attacker(rng)
        users = list(rng.choice(USERS, size=int(rng.integers(10, 21)), replace=False))
        dur = float(rng.uniform(360, 720))
        times = np.sort(rng.uniform(0, dur, size=len(users) * 2))
        for i, ts in enumerate(times):
            t = cap.t_at(t0s + float(ts))
            cap.auth.append(
                (t, _auth_rec(cap, t, ip, str(users[i % len(users)]), False, "webapp", "invalid_password"))
            )
        cap.label("SUSPICIOUS_PATTERN", name, "AUTH", ip, t0, cap.t_at(t0s + dur + 1), inst)
    elif name == "low_and_slow":
        ip = _attacker(rng)
        dur = float(rng.uniform(3600, 5400))
        dur = min(dur, total_s - t0s - 60)
        s = 0.0
        while s < dur:
            t = cap.t_at(t0s + s)
            cap.auth.append(
                (t, _auth_rec(cap, t, ip, str(rng.choice(USERS)), False, "vpn", "invalid_password"))
            )
            s += float(rng.uniform(150, 300))
        cap.label("SUSPICIOUS_PATTERN", name, "AUTH", ip, t0, cap.t_at(t0s + s), inst)
    elif name in ("http_scan", "http_scan_small"):
        ip = _attacker(rng)
        n = int(rng.integers(80, 300)) if name == "http_scan" else int(rng.integers(25, 41))
        dur = float(rng.uniform(180, 480)) if name == "http_scan" else 300.0
        times = np.sort(rng.uniform(0, dur, size=n))
        for ts in times:
            t = cap.t_at(t0s + float(ts))
            path = str(rng.choice(SCAN_PATHS))
            st = (
                200
                if path in ("/robots.txt", "/sitemap.xml")
                else int(rng.choice([404, 403], p=[0.88, 0.12]))
            )
            rec = {
                "timestamp": _iso(t, rng),
                "sensor": "web-01",
                "client_ip": ip,
                "method": "POST" if rng.random() < 0.1 else "GET",
                "path": path,
                "status": st,
                "bytes": int(rng.integers(150, 500)),
                "duration_ms": round(float(rng.lognormal(np.log(6), 0.4)), 2),
                "user_agent": "scanner (synthetic)",
            }
            cap.http.append((t, rec))
        cap.label("SUSPICIOUS_PATTERN", name, "HTTP", ip, t0, cap.t_at(t0s + dur + 1), inst)
    elif name == "authorized_batch":
        dur = float(rng.uniform(600, 1200))
        rate = float(rng.uniform(60, 120)) / 60.0
        n = int(dur * rate)
        for ts in np.sort(rng.uniform(0, dur, size=n)):
            t = cap.t_at(t0s + float(ts))
            rec = {
                "timestamp": _iso(t, rng),
                "sensor": "web-01",
                "client_ip": BATCH_HOST,
                "method": "GET",
                "path": f"/api/export/{int(rng.integers(1, 10000))}?format=csv",
                "status": 200,
                "bytes": int(rng.lognormal(np.log(50000), 0.3)),
                "duration_ms": round(float(rng.lognormal(np.log(80), 0.3)), 2),
                "user_agent": "batch-export/2.1",
            }
            cap.http.append((t, rec))
        cap.label("AUTHORIZED_LOAD", name, "HTTP", BATCH_HOST, t0, cap.t_at(t0s + dur + 1), inst)
    elif name == "ops_outage":
        dur = float(rng.uniform(480, 900))
        t1 = cap.t_at(t0s + dur)
        factor = float(rng.uniform(8, 15))
        for _t, rec in cap.http:
            if t0 <= _t < t1 and rec.get("client_ip") in CLIENTS:
                if rng.random() < 0.6:
                    rec["status"] = 503
                    rec["bytes"] = int(rng.integers(100, 300))
                rec["duration_ms"] = round(float(rec["duration_ms"]) * factor, 2)
        cap.label("OPERATIONAL_ANOMALY", name, "HTTP", "*", t0, t1, inst)
    else:  # pragma: no cover
        raise ValueError(name)


def _quality_noise(cap: _Capture, lines: list[str], kind: str) -> list[str]:
    rng = cap.rng
    out = []
    for line in lines:
        r = rng.random()
        if r < 0.003:
            out.append(line[: len(line) // 2])  # truncated / malformed JSON
            continue
        if r < 0.005:
            obj = json.loads(line)
            obj.pop("timestamp", None)
            out.append(json.dumps(obj))
            continue
        if r < 0.007:
            obj = json.loads(line)
            obj["timestamp"] = obj["timestamp"][:19].replace("T", " ")  # naive timestamp, no tz
            out.append(json.dumps(obj))
            continue
        if kind == "http" and r < 0.012:
            obj = json.loads(line)
            obj.pop("status", None)
            out.append(json.dumps(obj))
            continue
        out.append(line)
    return out


def _write(cap: _Capture, path: Path, events: list[tuple[datetime, dict[str, Any]]], kind: str) -> None:
    rng = cap.rng
    events.sort(key=lambda x: x[0])
    # Mild out-of-order arrival (within a few seconds) for ~1% of records.
    order = list(range(len(events)))
    for i in range(len(order) - 1):
        if rng.random() < 0.01:
            order[i], order[i + 1] = order[i + 1], order[i]
    lines = [json.dumps(events[i][1], separators=(",", ":")) for i in order]
    lines = _quality_noise(cap, lines, kind)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_dataset(dataset_id: str, seed: int = 1337, n_captures: int = 10, hours: float = 4.0) -> Path:
    if not SLUG_RE.match(dataset_id):
        raise ValueError("dataset_id must be a lowercase slug")
    if n_captures < 4 or n_captures > 40 or not (1.0 <= hours <= 12.0):
        raise ValueError("n_captures in [4, 40], hours in [1, 12]")
    root = get_config().datasets_dir / dataset_id
    if root.exists():
        raise FileExistsError("dataset directory exists; datasets are immutable, choose a new id")
    (root / "captures").mkdir(parents=True)
    pop = _population(seed)
    home_rng = np.random.default_rng([seed, 998])
    home = {u: str(home_rng.choice(CLIENTS)) for u in USERS}
    n_baseline = n_captures // 2
    captures_meta = []
    for i in range(n_captures):
        cid = f"cap{i:02d}"
        cap = _Capture(seed, i, BASE + timedelta(days=i), hours)
        gap = None
        if i in (1, n_captures - 1):
            total = hours * 3600
            # (1800, total-3600) for captures >= 1.5 h keeps earlier datasets reproducible; shorter ones scale down.
            lo, hi = (1800, total - 3600) if total - 3600 > 1800 else (0.25 * total, total - 1800)
            gs = float(cap.rng.uniform(lo, hi))
            gap = (gs, gs + 1500)
        _normal_http(cap, pop, gap)
        _normal_auth(cap, home)
        plan = [] if i < n_baseline else PLANS[(i - n_baseline) % len(PLANS)]
        for k, sc in enumerate(plan):
            _scenario(cap, sc, f"{cid}-{sc}-{k}")
        cdir = root / "captures" / cid
        cdir.mkdir()
        _write(cap, cdir / "http.ndjson", cap.http, "http")
        _write(cap, cdir / "auth.ndjson", cap.auth, "auth")
        labels = {
            "capture_id": cid,
            "label_source": "synthetic generator schedule (controlled); background traffic is benign by construction",
            "background_label": "BENIGN",
            "intervals": cap.intervals,
            "logging_gap_seconds": list(gap) if gap else None,
        }
        (cdir / "labels.json").write_text(json.dumps(labels, indent=1), encoding="utf-8")
        captures_meta.append(
            {
                "capture_id": cid,
                "scenario_group": cid,
                "start": cap.start.isoformat(),
                "end": cap.end.isoformat(),
                "files": {"HTTP": f"captures/{cid}/http.ndjson", "AUTH": f"captures/{cid}/auth.ndjson"},
                "labels": f"captures/{cid}/labels.json",
                "description": "baseline (normal only)" if not plan else "scenarios: " + ", ".join(plan),
            }
        )
    manifest = {
        "manifest_version": "atd.dataset.v1",
        "dataset_id": dataset_id,
        "name": f"Synthetic demo {dataset_id}",
        "provenance": "SYNTHETIC_DEMO",
        "privacy_class": "DEMO",
        "license": "Generated by this project's code; contains no third-party or real data",
        "usage_constraints": "Synthetic only. Identities are RFC 5737 documentation IPs and fake user names.",
        "description": "Deterministic synthetic HTTP + auth logs with controlled scenario schedule.",
        "generator": {
            "module": "ai_threat_detection.demo.synthetic",
            "version": GEN_VERSION,
            "seed": seed,
            "n_captures": n_captures,
            "hours_per_capture": hours,
            "time_base": BASE.isoformat(),
            "note": "timestamps are synthetic (not wall-clock); no latency claims derive from them",
        },
        "label_definition": {
            "unit": "entity-window overlap with labeled interval of the same entity ('*' = all entities of the domain)",
            "labels": {
                "SUSPICIOUS_PATTERN": "scripted threat-like pattern (auth burst/spray/low-and-slow, unknown-path burst)",
                "OPERATIONAL_ANOMALY": "service outage (5xx, latency) affecting all clients",
                "AUTHORIZED_LOAD": "permitted batch job with high request volume",
                "BENIGN": "background generated normal activity",
            },
        },
        "captures": captures_meta,
    }
    mpath = root / "dataset.json"
    mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return mpath
