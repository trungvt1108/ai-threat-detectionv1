# Operations

## Processes

- `manage.py runserver 127.0.0.1:8815` serves the console. Loopback only. Static files are served
  by the app in local settings.
- `manage.py runworker` executes queued jobs. Ctrl+C stops it. A job left `RUNNING` is recovered
  after `ATD_JOB_STALE_SECONDS` (default 300):
  - import/detect/import_dataset jobs are re-queued (max 3 attempts);
  - other jobs are marked FAILED.
- Jobs can be cancelled from **Jobs** by their creator or an admin. Cancellation is cooperative and
  happens within about 1 s at the next chunk.
- Every job has a timeout. `follow_source` always has a bounded `--duration`.
- Nothing is installed as a service, and nothing keeps running after you close the terminals.

## Budgets (env `ATD_*`, defaults)

| Variable | Default | Effect |
|---|---|---|
| `ATD_MAX_CPU_THREADS` | 2 | IsolationForest `n_jobs` and BLAS threads |
| `ATD_MAX_LINE_BYTES` | 65536 | Longer lines are rejected (`oversized_line`) |
| `ATD_MAX_FILE_BYTES` | 2 GiB | Larger files are refused |
| `ATD_MAX_JSON_ARRAY_BYTES` | 64 MiB | Whole-array JSON files above this are refused (use NDJSON) |
| `ATD_MAX_EVENTS_PER_JOB` | 2,000,000 | The import stops with `PARTIAL` and resumes next run |
| `ATD_IMPORT_CHUNK` | 2000 | Events per transaction/checkpoint |
| `ATD_MAX_EVENTS_PER_WINDOW` | 200,000 | Window flagged `window_event_cap_reached` |
| `ATD_RETENTION_DAYS` | 30 | `cleanup_data` cutoff |
| `ATD_MODEL_MAX_AGE_DAYS` | 90 | After this, a model is reported `STALE` (still scores, flagged) |

There is one training job at a time (global `training` lock). The measured work is small: fit
≈ 0.1–0.4 s and scoring ≈ 50k windows/s for the HTTP feature set on the development laptop. These
are single-batch wall-clock numbers from `docs/ACCEPTANCE.md`, not a benchmark.

## Health signals

- **Source health:** OK / STALE / MISSING / PERMISSION_DENIED / ERROR.
- **Ingest runs:** rejected and skipped reasons, late/future counts, largest event gap. Health
  rules HLTH-001/003 run after `import_logs` and after every capture of `import_dataset`.
- **Watermarks:** detection checkpoints per namespace.
- **Health rules:** HLTH-001 (parse failure ratio), HLTH-002 (stale follow source), HLTH-003 (gap
  over the declared `expected_max_gap_seconds`).
- **Drift page:** PSI per model feature vs train deciles, abstain ratio, score quantiles, model
  age.

Drift is a health signal. It is not attack evidence and does not trigger retraining.

## Detection on datasets

`detect --dataset <id>` (or **Chạy phát hiện trên mọi capture** on the dataset page) runs rules
and the active models over every capture namespace `ds:<id>/<capture>` with all windows closed.

- It uses each active model's window size. Without a model, it runs rules only with 300 s
  windows.
- Running it again adds no duplicate alerts.
- Experiments do not consume detection progress, so it also works after `create_experiment`.

## Model lifecycle

- **Train.** `train_detector` produces a `CANDIDATE`. Nothing activates automatically.
- **Activate.** `activate_model --model <id> --reason "..."` requires validation metrics and passes
  the integrity/compatibility gate. The switch is one DB transaction, and the artifact was written
  atomically earlier, so the worker never loads a half-written file.
- **Rollback.** `rollback_model --domain <D> --reason "..."` re-activates the previous model.
  `--deactivate` returns the domain to rules-only, shown as ML `UNTRAINED`.
- **Threshold.** `activate_model --threshold X` records a new threshold version with the reason.
- **Compatibility failures.** A scikit-learn/numpy/skops major.minor change, or a feature schema
  change, gives `INCOMPATIBLE`. A missing or tampered artifact gives `FAILED`. Either way the domain
  falls back to rules-only and the status is shown. Retrain under the new versions; do not edit
  registry rows.
- **No auto-retrain.** Incoming logs and analyst feedback never retrain. Retraining is an explicit
  batch: new dataset → new experiment.

## Backup / restore

Stop the server and worker first.

| What | Path | Note |
|---|---|---|
| Metadata DB | `.local/db/atd.sqlite3` (+ `-wal`/`-shm`) | Copy while stopped, or use `sqlite3 .backup` |
| Keys | `.local/keys/` | Back up separately. Without `pseudonym.key`, new data cannot be correlated with old data; without `integrity.key`, models cannot be loaded (`FAILED`) |
| Models | `.local/models/` | Restore together with the DB rows |
| Datasets / experiments | `.local/datasets/`, `.local/experiments/` | Hashes are checked on use |
| Reports | `.local/reports/`, `.local/public_drafts/` | |

Restore = put the files back in the same paths, run `manage.py migrate` (no-op if current), then
`manage.py doctor`.

## Source gaps

- A source that is MISSING / PERMISSION_DENIED / STALE appears on Overview and in health alerts. It
  is never read as "no threats".
- After an outage, use `import_logs` on the rotated files. Checkpoints prevent double counting.
  Events older than the closed watermark are flagged late and not added to old windows.

## Docker fixture (optional)

`fixtures/lab/docker-compose.yml` runs the fixture service in a container:

- non-privileged, read-only rootfs, all capabilities dropped, no-new-privileges;
- 256 MB / 0.5 CPU;
- its own network, published on `127.0.0.1:${ATD_FIXTURE_PORT:-18815}`;
- logs go to `.local/lab/docker-logs`;
- no Docker socket, home folder or secret mounts.

Clean up only this project:
`docker compose -f fixtures/lab/docker-compose.yml -p atd-fixture down --rmi local`.

Never run `docker system prune`. The `python:3.12-slim` base image stays in the local cache; remove
it with `docker image rm python:3.12-slim` if nothing else uses it.

## Cleanup

```
python manage.py cleanup_data                  # dry-run plan
python manage.py cleanup_data --apply          # delete per retention
python manage.py cleanup_data --namespace-prefix replay: --days 1 --apply   # drop old replays
```

Source log files and other projects' data are never deleted.
