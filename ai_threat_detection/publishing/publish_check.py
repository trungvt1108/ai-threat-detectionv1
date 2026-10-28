"""Read-only pre-publication gate.

Scope (reported explicitly in the output):
* Git: tracked files, staged files, and untracked files that are NOT ignored
  (what ``git add .`` would pick up); confirms runtime paths are ignored.
* Optional: drafts under ``<data_dir>/public_drafts`` (``--include-drafts``).
* Checks: forbidden file types (DB, model artifacts, keys, .env, raw logs),
  secret patterns, home paths / this machine's user and host names, emails
  outside the allowlist, non-documentation IP addresses, assistant/tool
  branding strings, dataset/model privacy classification of manifests.
* gitleaks is run when available on PATH; otherwise reported NOT_RUN.

"No findings" only means none of these checks matched within this scope; it is
not a guarantee. Nothing is modified, staged or uploaded.
"""

from __future__ import annotations

import fnmatch
import getpass
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ALLOWLIST_FILE = Path(__file__).with_name("allowlist.json")
MAX_SCAN_BYTES = 2 * 1024 * 1024

FORBIDDEN_GLOBS = [
    "*.sqlite3",
    "*.sqlite3-*",
    "*.db",
    "*.skops",
    "*.pkl",
    "*.pickle",
    "*.joblib",
    "*.key",
    "*.pem",
    "*.p12",
    ".env",
    ".env.*",
    "*.ndjson",
    "*.log",
    "*.jsonl",
    "*.pcap",
    "*.zip",
]
FORBIDDEN_ALLOWED = [".env.example", "fixtures/public/*.ndjson"]
MUST_BE_IGNORED = [".local/x", ".venv/x", "db.sqlite3", ".env", "model.skops"]

SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
    "assigned_secret": re.compile(
        r"(?i)\b(secret_key|api_key|apikey|access_token|auth_token|client_secret)\s*[:=]\s*['\"][A-Za-z0-9/+_\-]{16,}['\"]"
    ),
}
HOME_PATH = re.compile(
    r"(?i)\b[a-z]:\\{1,2}users\\{1,2}[a-z0-9._-]+|/home/[a-z0-9._-]+|/Users/[A-Za-z0-9._-]+"
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# RFC 2606 / 6761 reserved names are never real mailboxes.
EMAIL_OK_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    ".example",
    ".invalid",
    ".test",
    ".localhost",
)
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32")
]
BRANDING = re.compile(
    r"(?i)\b(claude|anthropic|chatgpt|openai|copilot)\b|co-authored-by|generated with|ai-generated|as an ai\b"
)
TEXT_EXT = {
    ".py",
    ".md",
    ".txt",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".yml",
    ".yaml",
    ".html",
    ".css",
    ".js",
    ".in",
    ".lock",
    ".example",
    ".gitignore",
    ".sh",
    ".ps1",
    "",
    ".dockerfile",
}


@dataclass
class Finding:
    severity: str  # HIGH | MEDIUM | LOW
    kind: str
    path: str
    line: int
    excerpt: str


def _git(repo: Path, *args: str) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    return [line for line in out.stdout.splitlines() if line.strip()]


def _load_allowlist() -> list[dict[str, str]]:
    if not ALLOWLIST_FILE.exists():
        return []
    return json.loads(ALLOWLIST_FILE.read_text(encoding="utf-8"))["entries"]


def _allowed(allow: list[dict[str, str]], f: Finding) -> bool:
    for a in allow:
        if a["kind"] == f.kind and fnmatch.fnmatch(f.path, a["path"]) and a.get("match", "") in f.excerpt:
            return True
    return False


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) > 120:
        s = s[:120] + "…"
    return re.sub(r"([A-Za-z0-9+/_\-]{6})[A-Za-z0-9+/_\-]{10,}", r"\1…", s)


def scan_text(rel: str, text: str, ctx: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        for kind, pat in SECRET_PATTERNS.items():
            if pat.search(line):
                out.append(Finding("HIGH", f"secret:{kind}", rel, i, _mask(line)))
        m = HOME_PATH.search(line)
        if m and "<" not in m.group(0):
            out.append(Finding("HIGH", "home_path", rel, i, _mask(m.group(0))))
        for ident in ctx["machine_identifiers"]:
            if ident and len(ident) >= 4 and re.search(rf"(?i)\b{re.escape(ident)}\b", line):
                out.append(Finding("HIGH", "machine_identifier", rel, i, "[machine user/host name]"))
        for em in EMAIL.findall(line):
            low = em.lower()
            if low.endswith(EMAIL_OK_DOMAINS) or low in ctx["identity_allowlist"]:
                continue
            out.append(Finding("MEDIUM", "email", rel, i, _mask(em)))
        for ip in IPV4.findall(line):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in n for n in DOC_NETS):
                continue
            sev = "MEDIUM" if addr.is_private else "LOW"
            out.append(Finding(sev, "ip_address", rel, i, ip))
        if BRANDING.search(line):
            out.append(Finding("MEDIUM", "assistant_branding", rel, i, _mask(line)))
    return out


def _check_manifest(rel: str, text: str) -> list[Finding]:
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(d, dict):
        return []
    pc = d.get("privacy_class")
    if pc is None and isinstance(d.get("dataset"), dict):
        pc = d["dataset"].get("privacy_class")
    if pc and pc not in {"DEMO", "PUBLIC_LICENSED"}:
        return [Finding("HIGH", "privacy_class", rel, 1, f"privacy_class={pc} is not publishable")]
    return []


def run_gitleaks(repo: Path) -> dict[str, Any]:
    exe = shutil.which("gitleaks")
    if not exe:
        return {"status": "NOT_RUN", "reason": "gitleaks not found on PATH"}
    with tempfile.TemporaryDirectory() as td:
        rp = Path(td) / "gl.json"
        proc = subprocess.run(
            [
                exe,
                "detect",
                "--no-git",
                "--source",
                str(repo),
                "--report-format",
                "json",
                "--report-path",
                str(rp),
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        findings = json.loads(rp.read_text(encoding="utf-8")) if rp.exists() and rp.stat().st_size else []
    return {"status": "RAN", "exit_code": proc.returncode, "findings": len(findings)}


def publish_check(
    repo: Path,
    include_drafts: bool = False,
    drafts_dir: Path | None = None,
    identity_allowlist: tuple[str, ...] = (),
) -> dict[str, Any]:
    repo = repo.resolve()
    is_git = bool(_git(repo, "rev-parse", "--is-inside-work-tree"))
    tracked = set(_git(repo, "ls-files")) if is_git else set()
    staged = set(_git(repo, "diff", "--cached", "--name-only")) if is_git else set()
    untracked = set(_git(repo, "ls-files", "--others", "--exclude-standard")) if is_git else set()
    candidates = sorted(tracked | staged | untracked)
    ignored_ok = {}
    if is_git:
        for p in MUST_BE_IGNORED:
            r = subprocess.run(
                ["git", "-C", str(repo), "check-ignore", "-q", p], capture_output=True, check=False
            )
            ignored_ok[p] = r.returncode == 0
    ctx = {
        "machine_identifiers": {getpass.getuser().lower(), socket.gethostname().lower()},
        "identity_allowlist": {s.lower() for s in identity_allowlist},
    }
    allow = _load_allowlist()
    findings: list[Finding] = []
    scanned = 0
    files: list[tuple[str, Path]] = [(rel, repo / rel) for rel in candidates]
    if include_drafts and drafts_dir and drafts_dir.exists():
        files += [
            (f"public_drafts/{p.relative_to(drafts_dir).as_posix()}", p)
            for p in drafts_dir.rglob("*")
            if p.is_file()
        ]
    for rel, path in files:
        if rel.startswith(".local/") or "/.local/" in rel:
            findings.append(
                Finding("HIGH", "runtime_data_tracked", rel, 0, "file under .local/ is visible to Git")
            )
        if any(fnmatch.fnmatch(Path(rel).name, g) for g in FORBIDDEN_GLOBS) and not any(
            fnmatch.fnmatch(rel, a) for a in FORBIDDEN_ALLOWED
        ):
            findings.append(
                Finding("HIGH", "forbidden_file_type", rel, 0, Path(rel).suffix or Path(rel).name)
            )
        if not path.exists() or not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_EXT and path.name not in {"Dockerfile", "LICENSE", "NOTICE"}:
            continue
        if path.stat().st_size > MAX_SCAN_BYTES:
            findings.append(Finding("LOW", "not_scanned_too_large", rel, 0, str(path.stat().st_size)))
            continue
        if path.resolve() == ALLOWLIST_FILE.resolve():
            continue  # the exception register itself (reviewed by humans, entries carry reasons)
        text = path.read_text(encoding="utf-8", errors="replace")
        scanned += 1
        findings.extend(scan_text(rel, text, ctx))
        if path.suffix == ".json" and ("privacy_class" in text):
            findings.extend(_check_manifest(rel, text))
    kept = [f for f in findings if not _allowed(allow, f)]
    suppressed = len(findings) - len(kept)
    for p, ok in ignored_ok.items():
        if not ok:
            kept.append(
                Finding("HIGH", "not_ignored", p, 0, "runtime path would not be ignored by .gitignore")
            )
    summary = {s: sum(1 for f in kept if f.severity == s) for s in ("HIGH", "MEDIUM", "LOW")}
    return {
        "scope": {
            "repo_is_git": is_git,
            "tracked_files": len(tracked),
            "staged_files": len(staged),
            "untracked_not_ignored_files": len(untracked),
            "drafts_included": include_drafts,
            "text_files_scanned": scanned,
            "checks": [
                "forbidden_file_types",
                "secrets",
                "home_paths",
                "machine_identifiers",
                "emails",
                "ip_addresses",
                "assistant_branding",
                "manifest_privacy_class",
                "gitignore_runtime_paths",
            ],
        },
        "gitleaks": run_gitleaks(repo),
        "staged_files": sorted(staged),
        "allowlisted_findings": suppressed,
        "summary": summary,
        "result": "FAIL" if summary["HIGH"] else ("REVIEW" if summary["MEDIUM"] else "PASS_WITHIN_SCOPE"),
        "findings": [asdict(f) for f in kept],
        "note": "PASS_WITHIN_SCOPE means no check matched in the listed scope; it is not a guarantee of no leaks. Human review still required.",
    }
