# Architecture

A single Django project (`config/`) with one Python package (`ai_threat_detection/`). Runtime state
lives in `.local/` and is never tracked.

The core runs without a network. The only network traffic is to the project's own fixture service
on loopback, and only when you run a lab capture.

```
                ┌────────────── sources/ ───────────────┐
 registered     │ reader.py (bounded lines, offsets)     │   normalization/
 file under  ─► │ adapters/ {http,auth} json/text, eve    │──► privacy.py (allowlist, scrub, path tokens)
 allowed root   │ ingest.py (chunks + checkpoint, 1 txn)  │    pseudonym.py (HMAC key in .local/keys)
                │ follow.py (rotate/truncate) / replay    │    timeparse.py (tz policy)
                └──────────────────┬──────────────────────┘
                                   ▼  Event (redacted, namespaced)
                features/builder.py  — event-time windows, watermark, DetectionCheckpoint
                                   ▼  FeatureWindow (computed values + coverage)
            ┌──────────────────────┴───────────────────────┐
     rules/engine.py (declarative,           ml/detector.py + registry/service.py
     allowlisted features/ops) ─► RuleDecision   (IsolationForest via skops, integrity-checked) ─► MLDecision
            └──────────────────────┬───────────────────────┘
                                   ▼  alerts/policy.py (OR, severity, cooldown grouping, suppression)
                         Alert + AlertDecision (evidence, versions) ─► triage / notifications (in-app)
                                   ▼
     experiments/ (datasets, split manifest, train/validate/test) ─► reports/ (md/html/json) ─► publishing/publish_check
```

## Modules

| Package | Responsibility |
|---|---|
| `sources/` | Source registry, path boundary checks, streaming reader, adapters, import / follow / replay, checkpoints, rejected-record accounting, source health |
| `normalization/` | Redaction, path normalization, keyed pseudonyms, timestamp policy, local key files |
| `features/` | Window config + explicit feature sets, pure feature computation (`compute.py`), DB window builder, drift |
| `rules/` | Rule schema/validation/evaluation, default pack, versioned `RuleConfig`, `RuleDecision` |
| `ml/` | IsolationForest training/scoring, threshold selection, baseline statistics (pure, no Django) |
| `registry/` | `ModelVersion`, atomic artifact writes, integrity/compatibility gate, activation/rollback/threshold history, `MLDecision` |
| `alerts/` | Detection pipeline, combination policy, grouping/suppression, health alerts, upstream IDS alerts, triage |
| `experiments/` | Dataset manifests, capture import, label resolution, split protocol, metrics, train/evaluate |
| `reports/` | Model cards, report export (private / public draft) |
| `worker/` | SQLite-backed job queue, locks, heartbeat, cancel/timeout, stale recovery, handlers |
| `lab/` | Loopback fixture service, scripted driver, lab capture packaging |
| `demo/` | Deterministic synthetic dataset generator |
| `publishing/` | Read-only publication gate |
| `accounts/` | Roles (admin / analyst / viewer) on Django groups |
| `ui/` | Views, templates, static CSS + ES module |
| `core/` | Audit log, security middleware, management commands |

## Key decisions

**One windowing implementation.** Experiments, replay and live detection all call
`features/builder.py::build_windows` and `features/compute.py`. A test checks that incremental
replay produces the same windows as a batch build. The acceptance run reproduced 836/836 HTTP and
76/76 AUTH windows of a test capture exactly through the replay path.

**Namespaces.** Events are stored in separate namespaces:

| Namespace | Holds |
|---|---|
| `live` | Imported / followed data |
| `replay:<name>` | Replays |
| `ds:<dataset>/<capture>` | Experiment captures |

Live counts never include replays or experiments, and windows never cross captures.

**Idempotency.** `event_id = sha256(namespace, source, file-head key, byte offset)`, or the
source's stable id field when configured. Each chunk's events, rejects and checkpoint commit in one
transaction. A crash re-reads at most one chunk, and the unique key de-duplicates it. The result is
at-least-once reading with idempotent writes. This is not end-to-end exactly-once.

**SQLite.** WAL, `synchronous=NORMAL`, a 20 s busy timeout, and IMMEDIATE write transactions. The UI
reads while the worker writes; a test covers this.

**Worker.**

- One job per `lock_key`: a single global `training` lock, plus one lock per source, dataset or
  namespace.
- Cooperative cancel/timeout through `ctx.check()`.
- A stale heartbeat re-queues idempotent kinds (import/detect/import_dataset) and marks other kinds
  FAILED.
- The UI only enqueues jobs. It never runs them.

**Resource budgets.**

- ML runs with `n_jobs` and BLAS threads capped at `ATD_MAX_CPU_THREADS` (default 2).
- Line, file, JSON-array and per-job event limits are set via `ATD_*`.
- Per-window event cap: `ATD_MAX_EVENTS_PER_WINDOW`.
- Window state is bounded by one window's events. No unbounded per-IP maps.

## Alert policy (alert-policy-v1)

| Detection source | Severity |
|---|---|
| RULE | highest triggered rule severity |
| ML_ANOMALY | low |
| RULE_AND_ML | rule severity + 1 level (max high) |
| UPSTREAM_IDS | Suricata severity 1→high, 2→medium, else low (the upstream rating, labelled as such) |
| DATA_QUALITY | low |

- **Combination:** a window raises an alert when any rule TRIGGERED, or when ML is `SCORED` with
  score ≥ threshold. `NOT_EVALUABLE` and `INSUFFICIENT_DATA` never raise alerts and never count as
  benign.
- **Grouping:** same namespace + domain + entity, within 15 minutes of an open alert. The new window
  is attached as an `AlertDecision`, so evidence is kept.
- **Suppression:** scoped to an entity and/or rule, with expiry (≤ 30 days), actor and reason.
  Suppressed alerts are stored and can be listed with a filter; they produce no notification.
- Every decision stores `cfg_hash`, rule versions, model id + threshold version and policy version.

## Explanations

- Rules show their observed values next to their thresholds.
- ML shows the score, threshold and train-reference percentile.
- Feature deviations are computed against train baseline quantiles: (value − median) / IQR, falling
  back to the p05–p99 spread when IQR = 0. This is labelled as descriptive deviation, not model
  attribution. No SHAP and no "feature X contributed N %".
