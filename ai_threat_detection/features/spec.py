"""Window configuration and explicit feature allowlists per domain.

Two independent domains (AUTH, HTTP). Each feature set lists exactly which
computed values feed the model and with which stateless transform. Nothing is
selected automatically ("all numeric columns"), so labels, scenario ids,
capture ids, file names or identities can never become inputs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

FEATURE_CODE_VERSION = "1.0.0"


@dataclass(frozen=True)
class WindowConfig:
    size_s: int = 300
    stride_s: int = 300
    allowed_lateness_s: int = 60
    min_events: int = 1
    origin: str = "unix_epoch_utc"
    timezone: str = "UTC"
    boundaries: str = "[start, end)"

    def __post_init__(self) -> None:
        if self.size_s <= 0 or self.stride_s <= 0 or self.stride_s > self.size_s:
            raise ValueError("require 0 < stride_s <= size_s")
        if self.size_s % self.stride_s != 0:
            raise ValueError("size_s must be a multiple of stride_s")
        if self.allowed_lateness_s < 0 or self.min_events < 1:
            raise ValueError("invalid lateness/min_events")

    @property
    def kind(self) -> str:
        return "tumbling" if self.size_s == self.stride_s else "sliding"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind
        d["feature_code_version"] = FEATURE_CODE_VERSION
        return d

    def config_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()[:16]

    @classmethod
    def from_dict(cls, d: dict) -> WindowConfig:
        keys = {"size_s", "stride_s", "allowed_lateness_s", "min_events", "origin", "timezone", "boundaries"}
        return cls(**{k: v for k, v in d.items() if k in keys})


DEFAULT_WINDOW = WindowConfig()


@dataclass(frozen=True)
class FeatureSet:
    name: str
    domain: str
    schema_version: str
    features: tuple[str, ...]
    transforms: dict[str, str]
    required_coverage: dict[str, float] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "domain": self.domain,
            "schema_version": self.schema_version,
            "features": list(self.features),
            "transforms": dict(self.transforms),
            "required_coverage": dict(self.required_coverage),
            "feature_code_version": FEATURE_CODE_VERSION,
        }


AUTH_V1 = FeatureSet(
    name="auth_v1",
    domain="AUTH",
    schema_version="atd.features.auth.v1",
    features=(
        "attempts",
        "failures",
        "failure_ratio",
        "distinct_users",
        "distinct_failed_users",
        "distinct_services",
        "max_failures_single_user",
        "success_after_3_failures",
    ),
    transforms={
        "attempts": "log1p",
        "failures": "log1p",
        "failure_ratio": "identity",
        "distinct_users": "log1p",
        "distinct_failed_users": "log1p",
        "distinct_services": "log1p",
        "max_failures_single_user": "log1p",
        "success_after_3_failures": "log1p",
    },
    required_coverage={"outcome": 0.8},
    description="Per source identity, auth attempt/failure statistics within the window.",
)

HTTP_V1 = FeatureSet(
    name="http_v1",
    domain="HTTP",
    schema_version="atd.features.http.v1",
    features=(
        "requests",
        "ratio_4xx",
        "ratio_404",
        "ratio_5xx",
        "distinct_paths",
        "distinct_path_ratio",
        "method_post_ratio",
        "method_other_ratio",
        "bytes_median",
        "latency_median_ms",
        "latency_p95_ms",
    ),
    transforms={
        "requests": "log1p",
        "ratio_4xx": "identity",
        "ratio_404": "identity",
        "ratio_5xx": "identity",
        "distinct_paths": "log1p",
        "distinct_path_ratio": "identity",
        "method_post_ratio": "identity",
        "method_other_ratio": "identity",
        "bytes_median": "log1p",
        "latency_median_ms": "log1p",
        "latency_p95_ms": "log1p",
    },
    required_coverage={"status": 0.8, "method": 0.8, "bytes": 0.8, "duration": 0.8},
    description="Per client identity, request volume, error ratios, path diversity, size and latency.",
)

HTTP_V1_CORE = FeatureSet(
    name="http_v1_core",
    domain="HTTP",
    schema_version="atd.features.http_core.v1",
    features=(
        "requests",
        "ratio_4xx",
        "ratio_404",
        "ratio_5xx",
        "distinct_paths",
        "distinct_path_ratio",
        "method_post_ratio",
        "method_other_ratio",
    ),
    transforms={
        "requests": "log1p",
        "ratio_4xx": "identity",
        "ratio_404": "identity",
        "ratio_5xx": "identity",
        "distinct_paths": "log1p",
        "distinct_path_ratio": "identity",
        "method_post_ratio": "identity",
        "method_other_ratio": "identity",
    },
    required_coverage={"status": 0.8, "method": 0.8},
    description="HTTP subset for sources without response size / duration fields.",
)

FEATURE_SETS: dict[str, FeatureSet] = {fs.name: fs for fs in (AUTH_V1, HTTP_V1, HTTP_V1_CORE)}
DEFAULT_FEATURE_SET = {"AUTH": "auth_v1", "HTTP": "http_v1"}
ML_DOMAINS = ("AUTH", "HTTP")

# All values computed per window (superset of model features; used by rules and explanations).
COMPUTED_FEATURES: dict[str, tuple[str, ...]] = {
    "AUTH": (
        "attempts",
        "failures",
        "successes",
        "unknown_outcomes",
        "failure_ratio",
        "distinct_users",
        "distinct_failed_users",
        "distinct_services",
        "distinct_hosts",
        "max_failures_single_user",
        "success_after_3_failures",
        "attempts_per_min",
    ),
    "HTTP": (
        "requests",
        "status_known",
        "count_2xx",
        "count_3xx",
        "count_4xx",
        "count_404",
        "count_5xx",
        "ratio_4xx",
        "ratio_404",
        "ratio_5xx",
        "distinct_paths",
        "distinct_path_ratio",
        "method_get_ratio",
        "method_post_ratio",
        "method_other_ratio",
        "bytes_median",
        "bytes_p95",
        "latency_median_ms",
        "latency_p95_ms",
        "requests_per_min",
    ),
}


def get_feature_set(name: str) -> FeatureSet:
    try:
        return FEATURE_SETS[name]
    except KeyError:
        raise ValueError(f"Unknown feature set {name!r}") from None
