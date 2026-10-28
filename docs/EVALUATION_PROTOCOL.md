# Evaluation protocol (atd-eval-protocol-v1)

This protocol was written before the reported experiments were trained or evaluated.
It is implemented in `ai_threat_detection/experiments/service.py` and
`ai_threat_detection/experiments/metrics.py`. Anything that deviates from it must be recorded
as a new experiment with its own limitations.

## 1. Datasets and provenance

Every dataset is a directory under `.local/datasets/<id>/` with a `dataset.json` manifest
(`atd.dataset.v1`) that records:

- provenance: `SYNTHETIC_DEMO`, `LAB_OBSERVED`, `USER_IMPORTED`, `PUBLIC_DATASET`
- privacy class: `DEMO`, `LAB`, `PRIVATE`, `PUBLIC_LICENSED`
- license / usage constraints, generator or capture procedure, seed
- captures: id, scenario group, start/end, raw files, label sidecar

The registry stores SHA-256 hashes of the manifest, every capture file and every label file.
Import re-checks the hashes. Each capture goes into its own namespace,
`ds:<dataset>/<capture>`, so a window can never span two captures and experiment data is never
counted as live data.

**Label source.** The labels come from the controlled schedule (the synthetic generator, or the
lab driver's measured start/end times). They live in a sidecar file and never appear in event
fields or features.

**Operator datasets (`build_dataset`).** Your own exported logs are split by event time into
fixed-length captures aligned to UTC (default one day). The last `--gap-seconds` (default 600) of
every capture are left out and counted in the manifest, so any split boundary has a purge gap of
at least that length (`create_experiment` refuses a window size + lateness larger than the gap).
Without a labels file the background label is `UNKNOWN`. With `--assume-benign` it is `BENIGN`,
recorded as the operator's unverified assertion. Optional label intervals use the same format as
the sidecar `intervals`.

Labels (precedence when intervals overlap): `SUSPICIOUS_PATTERN` > `OPERATIONAL_ANOMALY` >
`AUTHORIZED_LOAD` > background.

- A window gets a label when its `[start, end)` overlaps a labelled interval for the same entity.
  The entity `*` means all entities of the domain.
- The background label is `BENIGN` only if the capture declares that its background traffic is
  benign by construction. Otherwise it is `UNKNOWN`.
- `UNKNOWN` is never treated as negative. It is excluded from metrics and the exclusion count is
  reported.

## 2. Units and tasks

- **Unit.** One entity-window: an entity (pseudonymized source identity) × one event-time window.
  The default is a tumbling 300 s window with 60 s allowed lateness. The lab uses 10 s windows
  because its captures are short; lab metrics are never compared with 300 s results.
- **T1_SUSPICIOUS (primary).**
  - Positive: `SUSPICIOUS_PATTERN`.
  - Negative: `BENIGN`, `OPERATIONAL_ANOMALY`, `AUTHORIZED_LOAD`.
  - Rules: threat-category rules only. Operational rules (5xx/latency) are designed to fire on
    outages.
- **T2_ANOMALOUS (secondary).**
  - Positive: every non-background label.
  - Negative: `BENIGN`.
  - Rules: all window rules.
  - This task measures "deviates from the baseline", which includes harmless outages and
    authorized load. It shows that anomaly ≠ malicious.

## 3. Split (fixed before any fitting)

1. Order capture groups (`scenario_group`) by start time.
2. Assign whole groups chronologically to train / validation / test. The default proportions are
   0.5 / 0.2 / 0.3, or explicit `--counts a,b,c`.
3. A group never spans two splits.
4. Purge gap: `train.end + gap <= validation.start` and `validation.end + gap <= test.start`,
   where `gap = window size + allowed lateness`. If the gap is violated, the experiment is refused.
5. The split manifest (`.local/experiments/<id>/split_manifest.json`, hash stored in the DB)
   records:
   - assignment, time ranges, label counts per split/domain
   - window-id list hashes, window config, feature sets, pseudonym key id
   - leakage diagnostics: window/capture overlap (must be 0), entity overlap, and exact
     duplicate model vectors between test and train (reported, expected for tiny windows)
6. Experiments are immutable. A changed split, window or feature set needs a new experiment id.

## 4. Training (novelty detection)

- **Model.** `sklearn.ensemble.IsolationForest`, `contamination='auto'`, `bootstrap=False`, fixed
  `random_state` per experiment, `n_jobs = ATD_MAX_CPU_THREADS`.
- **Training data.** Train-split windows labelled `BENIGN` only. Non-baseline windows in the train
  split are excluded and counted. `--train-on-unknown` also admits `UNKNOWN` windows; this
  contamination risk is recorded in the model card.
- **Features.** Only the explicit allowlist of the feature set (`auth_v1`, `http_v1`,
  `http_v1_core`) with stateless transforms (`log1p` / identity).
  - Nothing is fitted on validation or test: no scaler, imputer or feature selection.
  - Windows that lack required coverage abstain (`INSUFFICIENT_DATA`) instead of being imputed.
- **Hyperparameters.** A fixed grid of 4 configurations (`ml/detector.py:HYPERPARAM_GRID`).
  - Selection is by validation average precision on T1.
  - If validation AP is undefined, the first configuration is used.
  - All trials are recorded.
- **Baseline statistics** (quantiles used in explanations and drift bins) and the **reference
  score distribution** (101 quantiles used for UI percentiles) come from the train windows only.
- **Score direction.** `anomaly_score = -score_samples(X)`; higher means more anomalous. A unit
  test asserts this direction.

## 5. Threshold selection (validation only)

- If validation has both T1 classes: the threshold that maximizes F1 on validation (T1). Ties go
  to the higher threshold.
- Otherwise: the 0.99 quantile of the validation scores.
- Unlabeled data (every validation window `UNKNOWN`) can only be trained with
  `--train-on-unknown`. The 0.99 quantile is then taken over all eligible validation windows,
  and `threshold_criterion.selected_on` says so. Test metrics are undefined (no known labels) and
  are reported as such, not as zero.
- The threshold and its criterion are stored in the registry. A later manual change creates a new
  threshold version with actor and reason, and is no longer "selected on validation".

Validation metrics are optimistic for ML because the threshold was chosen on that split. They are
labelled as such.

## 6. Final test

- `evaluate_detector` runs the frozen model + threshold + current rule versions on the test split.
- A second test evaluation of the same experiment/domain requires `--rerun-reason`. The run is
  then marked `test_previously_seen=true` and the report stops calling that test "unseen".

## 7. Methods compared (same eligible units, same split)

- `rules_only`: any TRIGGERED rule in scope (see the tasks above).
- `ml_only`: ML decision `SCORED` and score ≥ threshold. Abstentions count as "no ML alert"; their
  number is reported.
- `hybrid_or`: rules_only OR ml_only.

A rule that is `NOT_EVALUABLE` (missing feature) counts as not triggered and is never evidence of
benign behavior. The rule baseline is not tuned on test labels. If rules beat ML, the report says
so.

## 8. Metrics

Per method:

- **Classification counts:** TP/FP/FN/TN, confusion matrix, support per class.
- **Precision / recall / F1.** `None`/N/A when undefined (no positive predictions or no
  positives), never 0 % or 100 % by convention.
- **Accuracy:** secondary only.
- **False-positive rates:** FP per 1000 negative windows, and FP windows per observed hour (the
  summed duration of the split's captures, all entities).
- **Grouped alerts:** positives grouped per entity with a 15-minute cooldown, reported separately
  as total / containing a positive window / without a positive window. These are alert counts,
  not attack counts. Recall is per window; grouped counts are never mixed with window recall.
- **Per-scenario coverage:** windows flagged, and instances flagged (at least one window of the
  instance).

For ML ranking: `sklearn.metrics.average_precision_score` (step-wise, not interpolated) over the
scored windows, with support and prevalence.

**Timing:** wall-clock fit time; batch inference time and windows/s over the split on this
machine. This is not a production benchmark.

## 9. What results mean

- `SYNTHETIC_DEMO`: behavior on this generator only.
- `LAB_OBSERVED`: a local loopback fixture with a scripted driver. Not production validation.
- Small supports (for example a handful of suspicious HTTP windows) give unstable precision and
  recall. Reports print the supports next to every number.
- No public dataset is evaluated in v1 (`NOT_RUN`). The core does not depend on one.

## 10. Development history (disclosed)

- `synth-exp-1` on dataset `demo-synth-v1` (seed 1337) was a development run whose test split was
  evaluated once.
  - After seeing it, rule categories were introduced, so T1 now uses only threat-category rules.
    The reason was that HTTP-003 (5xx ratio) fired on the operational outage and dominated
    rules-only false positives.
  - That run and its seed are therefore development data. The reported synthetic experiment uses
    a new dataset (`synth-s4242`, seed 4242) created after this change. Its split was created
    before this protocol was finalized, and no fit or evaluation was done on it beforehand.
- The synthetic generator's scenario parameters were designed before any model was trained. They
  were not tuned to make any method win.
- 2026-10-28, after v1: text adapters, `build_dataset`, the unlabeled-threshold rule above and the
  `http_v1_core` choice were added. Two defects were fixed: dataset imports did not run health
  rules, and `create_experiment` advanced the live detection checkpoint of dataset namespaces, so
  `detect` on a dataset with an experiment skipped every window. Neither fix changes how
  experiment windows, splits, thresholds or metrics are computed, so the reported results stay as
  they are.
