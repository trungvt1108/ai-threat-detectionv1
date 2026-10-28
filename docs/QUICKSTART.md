# Quickstart

Every command below exists and was run while building v1. Paths are relative to the repo root; `<...>` are placeholders.

Requirements:

- Python 3.12 (3.11+ should work; tested on 3.12 / Windows 11)
- About 1 GB of disk for the demo
- No GPU, no cloud account, no API key
- Docker is optional and not needed for anything below

## 1. Install

PowerShell:
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install --require-hashes -r requirements\base.lock
# dev/test tools (pytest, ruff, mypy, bandit, playwright):
.\.venv\Scripts\python -m pip install --require-hashes -r requirements\dev.lock
```

Linux/macOS:
```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/base.lock
.venv/bin/python -m pip install --require-hashes -r requirements/dev.lock   # optional
```

Below, `python` means the venv interpreter: `.\.venv\Scripts\python` on Windows, `.venv/bin/python` on Linux.

## 2. Initialize runtime data, keys and an admin

```
python manage.py init_local        # creates .local/ and .local/keys/{django_secret,pseudonym,integrity}.key
python manage.py migrate           # also seeds the default rule pack and role groups
python manage.py create_user --username <admin-name> --role admin      # prompts for a password (min. 12 chars)
python manage.py create_user --username <analyst-name> --role analyst
python manage.py doctor            # versions, DB/WAL, key ids, parser schemas, ML status (prints no secrets)
```

- **Keys** live only in `.local/keys/`. Back them up separately (see OPERATIONS).
- **The pseudonymization key matters.** If you lose or replace it, the same IP or user maps to a
  different pseudonym. Correlation with older data and the labels of existing experiments stop
  matching.
- **Non-interactive user creation:** `--password-env <VAR>` reads the password from an
  environment variable.

## 3. Start / stop

```
python manage.py runserver 127.0.0.1:8815     # console: http://127.0.0.1:8815  (Ctrl+C to stop)
python manage.py runworker                    # second terminal: executes jobs queued from the UI (Ctrl+C to stop)
python manage.py runworker --once             # or: drain the queue once and exit
```

- The app binds to loopback only. Do not open the port to the LAN.
- CLI commands run their job inline by default. Add `--enqueue` to hand a job to the worker instead.
- Nothing keeps running after you stop these two processes.

## 4A. Offline demo path (synthetic, ~2 minutes)

```
python manage.py generate_synthetic_dataset --dataset-id synth-demo --seed 4242
python manage.py import_dataset --dataset synth-demo
python manage.py create_experiment --dataset synth-demo --exp-id synth-demo-w300 --window-size 300 --lateness 60 --counts 5,2,3
python manage.py train_detector --experiment synth-demo-w300 --domain AUTH
python manage.py train_detector --experiment synth-demo-w300 --domain HTTP
python manage.py list_models
python manage.py evaluate_detector --experiment synth-demo-w300 --domain AUTH --model <auth-model-id>
python manage.py evaluate_detector --experiment synth-demo-w300 --domain HTTP --model <http-model-id>
python manage.py activate_model --model <auth-model-id> --reason "demo activation"
python manage.py activate_model --model <http-model-id> --reason "demo activation"
python manage.py export_report --experiment synth-demo-w300
```

What these steps produce:

- The generated data is labelled `SYNTHETIC_DEMO`. It shows behavior on this generator only.
- `evaluate_detector` is the frozen test evaluation. A second run on the same experiment/domain
  requires `--rerun-reason` and is marked "test previously seen".

To see alerts flow through the live path, replay one test capture into a separate `replay:`
namespace. Replays never mix into live counts.

```
python manage.py register_source --name synth-replay-http --type http_json --root .local/datasets/synth-demo/captures/cap09 --provenance SYNTHETIC_DEMO --privacy-class DEMO
python manage.py replay_logs --source synth-replay-http --file http.ndjson --namespace demo-http
```

Then open the console and go to **Cảnh báo**, filtering on namespace `replay:demo-http`.

## 4B. Lab observation path (real fixture on loopback, ~10 minutes)

```
python manage.py lab_capture --dataset-id lab-obs-1 --profile default
python manage.py import_dataset --dataset lab-obs-1
python manage.py create_experiment --dataset lab-obs-1 --exp-id lab-obs-1-w10 --window-size 10 --lateness 2 --counts 4,2,2
python manage.py train_detector --experiment lab-obs-1-w10 --domain AUTH
python manage.py train_detector --experiment lab-obs-1-w10 --domain HTTP
python manage.py evaluate_detector --experiment lab-obs-1-w10 --domain <AUTH|HTTP> --model <model-id>
python manage.py export_report --experiment lab-obs-1-w10
```

How the capture works:

- `lab_capture` starts the project fixture service, a stdlib HTTP server, on `127.0.0.1` with a
  random port.
- A scripted driver sends harmless traffic to that server only: normal browsing, wrong passwords
  on fake fixture accounts, GETs to a short list of non-existent paths, fault mode (503 +
  latency), degraded/paused logging, and an authorized batch job.
- The fixture's own access/auth logs become a `LAB_OBSERVED` dataset.
- Lab windows are 10 s. Do not compare these results with 300 s results.

`--profile smoke` (~1 minute) only checks that the pipeline works.

## 5. Your own logs

### 5.1 Supported formats

| Your log | `--type` | Notes |
|---|---|---|
| nginx / Apache access log, default `combined` or `common` format | `http_combined` | Add ` rt=$request_time` at the end of the nginx `log_format` if you want latency features |
| SSH logins in `/var/log/auth.log`, `/var/log/secure`, or `journalctl -u ssh -o short-iso` | `auth_syslog` | Old-style lines without a year/zone need `--assume-timezone` |
| HTTP access records as JSON / NDJSON | `http_json` | Field names in SOURCES_AND_SCHEMAS |
| Authentication records as JSON / NDJSON | `auth_json` | |
| Suricata `eve.json` (alert/flow) | `suricata_eve` | Upstream signals only |

Compressed rotations (`.gz`) are not read. Decompress them first.

To try the text formats without a server, copy the synthetic samples from `fixtures/public/`
(`nginx_access_sample.txt`, `auth_sshd_sample.txt`) into `.local/inbox/<folder>/`.

### 5.2 Import and detect

1. Copy the exported files under an allowed root. The default roots are `.local/inbox`,
   `.local/lab` and `.local/datasets`. To read another folder, set `ATD_ALLOWED_SOURCE_ROOTS`
   (os.pathsep-separated) explicitly.
2. Register the source, import, and run detection:

   ```
   python manage.py register_source --name web --type http_combined --root .local/inbox/web --provenance USER_IMPORTED --privacy-class PRIVATE
   python manage.py register_source --name ssh --type auth_syslog --root .local/inbox/ssh --assume-timezone Asia/Ho_Chi_Minh
   python manage.py import_logs --source web --file access.log --close-all-windows
   python manage.py import_logs --source ssh --file auth.log --close-all-windows
   python manage.py follow_source --source web --file access.log --duration 600   # bounded follow of a growing file
   ```

3. Alerts appear in **Cảnh báo** (namespace `live`). The source page shows accepted, rejected and
   skipped line counts.

**ML models.** A model trained on other data (the synthetic demo, for example) scores your logs
against someone else's "normal" and produces many false positives. Before importing your own
logs, either:

- run `rollback_model --domain AUTH --deactivate --reason "..."` (same for HTTP), so the domain
  runs rules-only and the UI shows ML `UNTRAINED`; or
- train a model on your own data (5.3).

### 5.3 Train a model on your own logs

Collect at least several days, so there are enough captures and windows.

```
python manage.py build_dataset --dataset-id my-logs --http-file .local/inbox/web/access.log --http-type http_combined --auth-file .local/inbox/ssh/auth.log --auth-type auth_syslog --assume-timezone Asia/Ho_Chi_Minh
python manage.py import_dataset --dataset my-logs
python manage.py create_experiment --dataset my-logs --exp-id my-logs-w300 --http-feature-set http_v1_core
python manage.py train_detector --experiment my-logs-w300 --domain HTTP --train-on-unknown
python manage.py train_detector --experiment my-logs-w300 --domain AUTH --train-on-unknown
python manage.py evaluate_detector --experiment my-logs-w300 --domain HTTP --model <id>
python manage.py activate_model --model <id> --reason "trained on our own logs"
python manage.py detect --dataset my-logs        # optional: alerts on the historical captures
```

- **Captures.** `build_dataset` splits the files into one capture per UTC day (change with
  `--capture-hours`). It leaves out the last 10 minutes of each day as the purge gap. It needs at
  least 3 captures with events.
- **Copies stay local.** The capture files are copies of your lines under
  `.local/datasets/my-logs/` (ignored by Git, privacy `PRIVATE`).
- **Unlabeled logs.** Without labels, windows are `UNKNOWN`. Training then needs
  `--train-on-unknown`: the model learns from whatever happened in those days, attacks included.
  The threshold is the 0.99 quantile of validation scores, and test metrics stay undefined.
- **Labels.** If you know when incidents happened, pass `--labels labels.json`, a list of
  `{"label": "SUSPICIOUS_PATTERN", "domain": "AUTH", "entity": {"kind": "ip", "value": "203.0.113.66"}, "start": "...+07:00", "end": "...+07:00"}`.
  Then precision and recall become measurable. Use `--assume-benign` only if you are sure the
  rest of the traffic is benign.
- **Feature set.** Use `--http-feature-set http_v1_core` when the access log has no duration
  (`rt=`). Otherwise HTTP windows abstain.
- **Data size.** AUTH needs at least 20 eligible training windows. A few hours of SSH logs on a
  quiet server are not enough.

## 6. Tests and checks

```
python -m pytest                      # default: offline, deterministic (lab/browser excluded)
python -m pytest -m lab               # real fixture on loopback (~1 min)
python -m pytest -m browser           # real browser via Playwright using the system Edge/Chrome channel
python -m ruff check .
python -m mypy
python -m bandit -q -r ai_threat_detection config -c pyproject.toml
python manage.py publish_check        # read-only: what Git would publish
```

## 7. Cleanup

- `python manage.py cleanup_data` shows what retention would delete (dry-run). Add `--apply` to
  delete. It never touches source log files.
- Deleting `.local/` removes everything: DB, keys, datasets, models, reports. Do this only if you
  no longer need them.
