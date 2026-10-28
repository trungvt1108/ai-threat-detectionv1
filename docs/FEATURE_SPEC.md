# Feature specification (feature code 1.0.0)

## Windows

- **Kind.** Tumbling (`stride = size`) or sliding (`size % stride == 0`). Aligned to the Unix epoch
  in UTC, half-open `[start, end)`.
- **Entity.** AUTH and HTTP both key on the source/client identity pseudonym (`entity_key`).
  Events without an entity are stored but excluded from windows.
- **Close rule.** A window closes when `end <= watermark - allowed_lateness`. The watermark is the
  latest non-excluded event time in the namespace/domain, the replay clock, or `+∞` when a finished
  capture is finalized.
- **Prediction time.** `available_at = end + allowed_lateness`. Features only use events that
  arrived before the window closed. Nothing from the future of a session is aggregated.
- **Late events.** Events for an already-closed range are flagged at ingest, excluded and counted.
  Historical windows and alerts are never rewritten.
- **Minimum support.** `min_events` (default 1). Below it, ML abstains.
- **Config identity.** The config hash covers size, stride, lateness, min_events, origin, timezone,
  boundaries and the feature code version.

| Config | size / stride / lateness | Used for |
|---|---|---|
| Default | 300 s / 300 s / 60 s | Live detection, synthetic experiment |
| Lab | 10 s / 10 s / 2 s | Lab captures (45 s each); not comparable to 300 s results |

## Computed values per window

**AUTH:** `attempts`, `failures`, `successes`, `unknown_outcomes`, `failure_ratio`,
`distinct_users`, `distinct_failed_users`, `distinct_services`, `distinct_hosts`,
`max_failures_single_user`, `success_after_3_failures`, `attempts_per_min`.

- `failure_ratio` = failures / (failures + successes). It is `None` if no outcome is known. Missing
  or unknown outcomes are not counted as success.
- `success_after_3_failures` counts successes of a user that follow ≥ 3 consecutive failures of
  that user from the same entity within the window, in time order.

**HTTP:** `requests`, `status_known`, `count_2xx`, `count_3xx`, `count_4xx`, `count_404`,
`count_5xx`, `ratio_4xx`, `ratio_404`, `ratio_5xx`, `distinct_paths`, `distinct_path_ratio`,
`method_get_ratio`, `method_post_ratio`, `method_other_ratio`, `bytes_median`, `bytes_p95`,
`latency_median_ms`, `latency_p95_ms`, `requests_per_min`.

- Ratios use the number of events where that field is known as the denominator.
- Percentiles use numpy linear interpolation.

**Coverage** is stored per window:

- AUTH: `outcome`, `user`, `service`
- HTTP: `status`, `method`, `path`, `bytes`, `duration`

## Model feature sets (explicit allowlists)

| Set | Domain | Features (order matters) | Transform | Required coverage |
|---|---|---|---|---|
| `auth_v1` | AUTH | attempts, failures, failure_ratio, distinct_users, distinct_failed_users, distinct_services, max_failures_single_user, success_after_3_failures | log1p on counts, identity on ratio | outcome ≥ 0.8 |
| `http_v1` | HTTP | requests, ratio_4xx, ratio_404, ratio_5xx, distinct_paths, distinct_path_ratio, method_post_ratio, method_other_ratio, bytes_median, latency_median_ms, latency_p95_ms | log1p on counts/sizes/latency, identity on ratios | status, method, bytes, duration ≥ 0.8 |
| `http_v1_core` | HTTP | first 8 of `http_v1` | as above | status, method ≥ 0.8 |

The HTTP feature set is fixed per experiment: `create_experiment --http-feature-set http_v1_core`
or the experiment form in the UI. Choose `http_v1_core` for sources without response duration,
such as plain combined logs. A model trained on a set keeps it for live detection.

- **No learned preprocessing.** Transforms are stateless, so nothing can be fit on
  validation/test data.
- **Abstain instead of impute.** A window below required coverage, or with any `None` model
  feature, is `INSUFFICIENT_DATA`. It is not imputed and not treated as low risk.
- **Never inputs:** raw or pseudonymized identities, URLs/query strings, labels, scenario ids,
  capture ids, file names, sensor/source ids, generator seeds, and anything from EVE alerts.
  Tests check that changing those metadata leaves the matrix and score unchanged.
- **One code path.** Training and inference both use `features/compute.py` +
  `ml/detector.py::build_matrix`.
- **Baseline stats** (quantiles, decile bins for PSI) and the 101-point reference score
  distribution come from train windows only.
