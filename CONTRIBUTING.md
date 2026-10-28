# Contributing

## Setup

See `docs/QUICKSTART.md`. Install `requirements/dev.lock` for the tooling.

Dependencies are pinned with hashes:

1. Edit `requirements/base.in` or `requirements/dev.in`.
2. Regenerate the lockfile with
   `pip-compile --generate-hashes --strip-extras -o requirements/base.lock requirements/base.in`
   (and the same for `dev`).

## Before sending a change

```
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m bandit -q -r ai_threat_detection config -c pyproject.toml
python -m pytest                 # offline, deterministic
python -m pytest -m lab          # if you touched lab/ or ingestion
python -m pytest -m browser      # if you touched ui/ (needs a local Edge or Chrome)
python manage.py publish_check
```

## Rules of the road

- **Rules and features.** Never add a feature or rule input derived from labels, scenario/capture
  ids, file names, identities or EVE alert fields. Feature sets are explicit allowlists. A new
  computed value must be added to `COMPUTED_FEATURES` and tested.
- **Thresholds.** Change rule thresholds through `update_rule` (versioned, with a reason). Never
  tune them against test labels.
- **Evaluation protocol.** Any change to splits, windows, features, threshold rules or task
  definitions after test results have been seen requires a **new experiment** and an entry in
  `docs/EVALUATION_PROTOCOL.md` §10.
- **Test data.** Use synthetic data with RFC 5737 IPs and fake names. Never commit real logs,
  models, DB files or keys.
- **Writing.** Use concrete wording about inputs, behavior, evidence and limits. Do not call a
  high anomaly score an attack or a compromise.

## License

No license has been chosen yet. Until the owner adds one, all rights are reserved by the author.
Third-party components keep their own licenses: Django, scikit-learn and numpy are BSD-3-Clause;
skops is MIT.
