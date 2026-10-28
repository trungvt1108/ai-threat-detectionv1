# Privacy and publishing

## Data handling

- **Allowlist before persistence.** Adapters copy only the fields listed in SOURCES_AND_SCHEMAS.
  Headers, cookies, Authorization, bodies, query values, user agents, EVE payload/packet/http/tls
  objects, passwords, OTPs and tokens are never stored.
- **Scrubbing.** The few free-text values kept (sensor names, Suricata signature/category) go
  through a secret scrubber: JWT, bearer/basic credentials, cloud tokens, `key=value` secrets,
  URL userinfo, e-mail addresses.
- **Pseudonyms.** HMAC-SHA256 over scope + kind + canonical value, using the key in
  `.local/keys/pseudonym.key`. They are stable for grouping/correlation. This is **not
  anonymization**: anyone with the key, or able to test candidate values against it, can
  re-identify. Manifests record the key id (a hash of the key, not the key). Changing the key or
  scope breaks correlation and experiment labels; `create_experiment` refuses a key mismatch.
- **Identities are never model features.** Raw or pseudonymized identities are used only for
  grouping.
- **Raw identity view.** Off by default:
  - stored only for sources with `store_raw_identity=True`;
  - shown only to admins when `ATD_ALLOW_RAW_IDENTITY_VIEW=true`;
  - every view is audited;
  - never exported.
- **Invalid lines.** Stored as locator + SHA-256 + reason. A scrubbed, IP-masked 120-character
  preview is stored only when the source enables it.
- **Retention.** `cleanup_data` (dry-run by default) deletes events, rejects and windows older than
  `ATD_RETENTION_DAYS`. Alerts with their evidence windows, models, experiments and the audit log
  are kept.
- **No copies of source logs.** Raw source logs are never copied into the repo. Datasets live
  under `.local/datasets` (ignored by Git).

## Classification

| Class | Examples | Publishable? |
|---|---|---|
| `PRIVATE` | Your imported logs, models/baselines trained on them, private split manifests | No |
| `LAB` | Fixture logs from `lab_capture` | Only after explicit review (they contain no third-party data, but the default is "no") |
| `DEMO` | Synthetic generator output, `fixtures/public/` | Yes, after review |
| `PUBLIC_LICENSED` | Public datasets with a license that allows it | Per license; a model trained on them is not automatically shareable |

## Publishing workflow (nothing is automated)

1. `python manage.py export_report --experiment <id> --public-draft` writes a draft under
   `.local/public_drafts/`:
   - entity and source names replaced by aliases;
   - no event samples;
   - no paths.
2. Review the draft yourself, both the content and the re-identification risk.
3. `python manage.py publish_check --include-drafts` (read-only) scans:
   - Git-visible files (tracked, staged, untracked-not-ignored);
   - forbidden file types (DB, models, keys, `.env`, raw logs);
   - secret patterns, home paths, this machine's user/host name;
   - e-mails outside the allowlist, non-documentation IPs;
   - assistant/tool branding strings;
   - manifest privacy classes;
   - that runtime paths are ignored by `.gitignore`.

   It runs gitleaks if gitleaks is on PATH and reports NOT_RUN otherwise.
4. Fix or justify findings. Exceptions for synthetic test data are listed one by one, with
   reasons, in `ai_threat_detection/publishing/allowlist.json`. There are no blanket rule
   disables.
5. Stage, commit and push yourself. The project never stages, commits, pushes, uploads or deploys.

"PASS_WITHIN_SCOPE" means no check matched in the listed scope. It is not a guarantee.

**Public identity.** You may publish your own chosen name or e-mail (for example as Git author).
List them in `ATD_PUBLIC_IDENTITY_ALLOWLIST` so `publish_check` does not flag them. This never
covers personal data found in logs.
