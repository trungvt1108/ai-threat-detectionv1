# Acceptance record (local v1, 2026-10-28)

**Environment.** Windows 11, Python 3.12.10, Django 5.2.18, scikit-learn 1.9.1, numpy 2.5.4,
skops 0.16.0, CPU only, `ATD_MAX_CPU_THREADS=2`.

Everything below was actually run. Runtime identifiers such as model ids and report ids refer to
the private `.local/` store and are not published.

## Status by acceptance criterion

| Criterion | Status | Evidence |
|---|---|---|
| A. Install/start/stop per quickstart, no cloud key/GPU | Done | `init_local`, `migrate`, `create_user`, `doctor`, `runserver 127.0.0.1:8815`, `runworker --once` |
| B. AUTH/HTTP ingestion, features, rules; EVE scoped | Done | CLI import/replay/follow; EVE sample: 3 accepted, 1 `unsupported_event_type`, upstream alert grouped; flow = UPSTREAM_ONLY |
| C. Two model domains train/score/save/load + model cards | Done | 4 models (2 synthetic, 2 lab); save→load max abs score diff = 0.0 |
| D. Reproducible protocol/splits/thresholds; leakage checks | Done | Split manifests with 0 window/capture overlap; validation-chosen thresholds; test evaluated once per model; reruns refused without a reason |
| E. Synthetic and lab-observed end-to-end | Done | `synth-s4242` (SYNTHETIC_DEMO), `lab-obs-1` (LAB_OBSERVED, 4,412 real requests to the loopback fixture) |
| F. UI/triage/reports/public gate on the real backend | Done | Browser walkthrough of the real server (system Edge, 0 console errors); reports exported; `publish_check` run |
| G. Tests/lint/typecheck/security | Done | See "Checks" |
| H. Nothing staged/committed/pushed/deployed/uploaded | Done | `git` repo initialized locally; no commits; `publish_check` reports 0 staged files |
| Public dataset external holdout | **NOT_RUN** | No suitable licensed AUTH/HTTP dataset selected; core does not depend on one |
| Production / real-traffic validation | **NOT_RUN** | Out of scope; no production logs used |
| gitleaks | **NOT_RUN** | Not installed on this machine; `publish_check` reports it; run it when available |

## Synthetic experiment `synth-s4242-w300` (SYNTHETIC_DEMO)

**Setup**

- Dataset: seed 4242, 10 captures of 4 h.
- Split: train 5 / validation 2 / test 3 capture groups, chronological, 360 s purge gap.
- Windows: 300 s tumbling, 60 s lateness.
- An earlier development run (seed 1337) is disclosed in EVALUATION_PROTOCOL §10.

**Test split, task T1_SUSPICIOUS** (unit: entity-window; 12 observed hours)

| Domain | Method | Precision | Recall | F1 | TP/FP/FN/TN | FP per 1000 neg. windows | Grouped alerts (without positive) |
|---|---|---|---|---|---|---|---|
| AUTH (17 pos / 225 neg) | rules_only | 1.000 | 0.412 | 0.583 | 7/0/10/225 | 0.0 | 3 (0) |
| | ml_only | 0.586 | 1.000 | 0.739 | 17/12/0/213 | 53.3 | 16 (12) |
| | hybrid_or | 0.586 | 1.000 | 0.739 | 17/12/0/213 | 53.3 | 16 (12) |
| HTTP (8 pos / 2690 neg) | rules_only | 1.000 | 0.500 | 0.667 | 4/0/4/2690 | 0.0 | 2 (0) |
| | ml_only | 1.000 | 0.750 | 0.857 | 6/0/2/2690 | 0.0 | 3 (0) |
| | hybrid_or | 1.000 | 0.875 | 0.933 | 7/0/1/2690 | 0.0 | 3 (0) |

**ML ranking (average precision over scored windows):** AUTH 0.830 (242 scored); HTTP 1.000
(2,692 scored, 6 abstained). HTTP has only 8 positive windows, so this AP is not robust.

**T2_ANOMALOUS (HTTP, 107 positive windows: 91 outage, 8 authorized batch, 8 suspicious).**
rules_only F1 0.514, ml_only 0.106, hybrid_or 0.544. The IsolationForest threshold was selected for
T1, and the model flagged none of the outage or batch-job windows. The operational 5xx rule
(HTTP-003) caught part of the outage. Anomaly ≠ malicious, and the model's "anomaly" here is
narrow.

**Observations**

- **AUTH ML vs rules.** The model catches every suspicious window, including all 9 low-and-slow
  windows that no rule catches. The cost is 12 false-positive windows among 225 benign ones.
- **Why the AUTH ML looks strong.** Synthetic normal auth traffic rarely contains failures.
  Effectively, "a window with failures from this entity" is unusual here. Real environments have
  more failure noise, so expect more false positives.
- **HTTP.** Rules miss the small scan (2 windows); ML catches it.

**Timing (this laptop, single batch over the test split).** HTTP: fit 0.13 s, 2,698 windows scored
in 0.051 s. AUTH: fit 0.32 s, 242 windows in 0.030 s.

## Lab experiment `lab-obs-1-w10` (LAB_OBSERVED)

**Setup**

- 8 captures × 45 s. The project fixture ran as a separate process on 127.0.0.1; a scripted driver
  generated the traffic.
- Split 4/2/2. Windows 10 s / lateness 2 s.
- The test split covers only 90 s of observation, so per-hour rates are extrapolations and are not
  meaningful.

**Test split, T1_SUSPICIOUS**

| Domain | Method | Precision | Recall | F1 | TP/FP/FN/TN |
|---|---|---|---|---|---|
| AUTH (5 pos / 38 neg) | rules_only | 1.000 | 0.800 | **0.889** | 4/0/1/38 |
| | ml_only | 0.714 | 1.000 | 0.833 | 5/2/0/36 |
| | hybrid_or | 0.714 | 1.000 | 0.833 | 5/2/0/36 |
| HTTP (4 pos / 67 neg) | rules_only | 1.000 | 0.250 | 0.400 | 1/0/3/67 |
| | ml_only | 0.400 | 0.500 | 0.444 | 2/3/2/64 |
| | hybrid_or | 0.500 | 0.750 | 0.600 | 3/3/1/64 |

**Observations**

- In the lab AUTH test, the **rule baseline beats ML** on F1. This is reported as is.
- In the lab HTTP T2 task, rules_only (F1 0.615) beat ml_only (0.174). None of the 12
  fault-mode windows were flagged by ML.
- Supports are very small (4–5 positive windows), so differences of one window change the metrics
  a lot.
- The degraded-logging scenario produced real rejects in capture c05: 29 `missing_timestamp`, 23
  `missing_timezone` (HTTP).

## Live-path reproducibility

The synthetic models were activated, then test capture `cap09` was replayed with `replay_logs` into
`replay:` namespaces through the live detection path. The replay reproduced **836/836 HTTP and
76/76 AUTH windows with identical feature values** and identical windows to the experiment.
`tests/test_experiment_eval.py::test_replay_with_active_model_reproduces_experiment_scores` checks
scores against direct scoring with tolerance < 1e-12.

The replay created 8 HTTP alerts and 4 AUTH alerts:

- RULE_AND_ML: one HTTP-001/HTTP-002 + ML alert, and one AUTH-001 + ML alert;
- ML_ANOMALY: 3 AUTH alerts;
- RULE (operational HTTP-003): 7 alerts during the outage.

## Checks

| Check | Result |
|---|---|
| `pytest` (default, offline) | 95 passed (83 at v1 + 12 for the additions below) |
| `pytest -m lab` (real fixture on loopback) | 2 passed |
| `pytest -m browser` (Playwright + system Edge) | 2 passed |
| `ruff check` | pass |
| `mypy` (pure modules listed in pyproject) | pass |
| `bandit` | 0 high; medium/low findings reviewed (fixture URL opens on loopback, fixed-arg git/python subprocess calls, `random` for traffic simulation, placeholder/fake passwords in fixtures) |
| Docker fixture | Built and run once: non-privileged, read-only, cap_drop ALL, loopback port; served real requests; removed afterwards by project label |
| Real-browser walkthrough of `runserver` | 10 pages + alert detail, 0 console errors. It found and fixed: static files not served without DEBUG; wrong numeric formatting; IQR=0 deviation scale |

## Additions after v1 (2026-10-28)

A review of the running console found two gaps for real use (only JSON input; no supported way
to train on your own logs) and two defects. All four were addressed and tested.

| Item | Change | Evidence |
|---|---|---|
| Text logs | New adapters `http_combined` (nginx/Apache common/combined) and `auth_syslog` (sshd lines, RFC 3339 or BSD syslog). Out-of-scope lines are *skipped*, not rejected | `tests/test_text_sources.py` (parsing, privacy, skip accounting, rules firing) |
| Own-data datasets | `build_dataset` (time-based captures with purge margin, optional labels); `create_experiment --http-feature-set`; unlabeled-validation threshold rule (EVALUATION_PROTOCOL §5) | End-to-end test on the public samples |
| Dataset detection | `detect --dataset <id>` and a button on the dataset page | Same test; re-running adds no duplicates |
| Defect 1 | `import_dataset` did not run health rules, so degraded logging in a capture raised no HLTH alert | Fixed. On `lab-obs-2`, capture c05 now has HLTH-001 for HTTP (53 of 502 lines rejected) and AUTH (5 of 43) |
| Defect 2 | `create_experiment` advanced the detection checkpoint of dataset namespaces, so `detect` after an experiment evaluated nothing | Fixed; migration `atd_features.0002` removed 36 checkpoints that only experiments had created (`lab-obs-1`, `synth-s4242`) and kept the 8 with real detection output (`lab-obs-2`) |

**Public samples through the CLI** (`fixtures/public/nginx_access_sample.txt`,
`auth_sshd_sample.txt`; synthetic, 4 h):

- `import_logs`: HTTP 1,501 accepted / 0 rejected; AUTH 51 accepted / 0 rejected / 12 skipped
  (4 cron, 8 `Invalid user` notices).
- Rules raised exactly the two planted incidents:
  - the path scan → HTTP-001;
  - the guessing burst that ended in a login → AUTH-001 + AUTH-003 (high).
- `build_dataset --capture-hours 1` gave 4 captures. 240 HTTP and 3 AUTH lines fell in the purge
  margins.
- `train_detector --train-on-unknown` produced an HTTP candidate (threshold = validation 0.99
  quantile). Its test metrics are undefined because every window is UNKNOWN, and they are
  reported that way.
- AUTH training was refused because there were fewer than 20 training windows. That is the
  intended data-size guard.

**Checks after the additions:**

- pytest: 95 default, 2 lab and 2 browser tests passed.
- ruff, ruff format, mypy (now including `experiments/builder.py`) and `manage.py check` pass.
  No pending migrations.
- bandit: no new findings.
- `publish_check --include-drafts`: PASS_WITHIN_SCOPE with the same 9 allowlisted items.
  gitleaks was still NOT_RUN.

## Reproduce

See `docs/QUICKSTART.md` §4A / §4B. These steps are the same commands with
`--dataset-id synth-s4242 --seed 4242`, `--exp-id synth-s4242-w300 --counts 5,2,3`, and
`--dataset-id lab-obs-1 --profile default`, `--exp-id lab-obs-1-w10 --window-size 10 --lateness 2
--counts 4,2,2`.

The synthetic dataset was verified byte-identical when regenerated from the seed on the same platform (files are written with the platform line ending; parsed events are the same either way). Lab captures depend on real timing and
are not byte-reproducible.
