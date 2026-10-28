# Threat model (local v1)

## Assets

- Normalized events and windows. They may contain pseudonymized identities of other people.
- Raw identity mappings, but only when a source enables `store_raw_identity`.
- Keys in `.local/keys`: Django secret, pseudonymization key, artifact integrity key.
- Model artifacts and train baselines. These are derived from possibly private data.
- Analyst notes, the audit log, and reports.

## Trust boundaries and controls

| Boundary | Threat | Control |
|---|---|---|
| Log files → importer | Malicious/oversized/garbled records, embedded secrets, a "command" field | `json.loads` only (no eval/exec/pickle/YAML); text formats matched by fixed, anchored regular expressions with bounded repetition (tested against 64 KiB lines); line, file, array and event limits; allowlisted fields; scrubbing; rejected lines stored as hash + reason only; fields are never executed |
| Filesystem | Reading outside intended folders | Explicit source registration; roots restricted to `ATD_ALLOWED_SOURCE_ROOTS`; resolved-path containment and pattern checks on every access |
| Browser ↔ console | Other websites driving `127.0.0.1:8815` (CSRF, DNS rebinding, clickjacking) | Session auth on every page; CSRF tokens; `SameSite=Strict` cookies; Origin check on unsafe methods; `Sec-Fetch-Site: cross-site` blocked; `ALLOWED_HOSTS` restricted to loopback names; CSP `script-src 'self'` (no inline script); `X-Frame-Options: DENY`; `no-store` |
| Roles | Privilege misuse | Server-side role checks on every view (viewer < analyst < admin); GET never mutates; job cancel limited to its owner or an admin; every change to sources, rules, thresholds, models, suppressions, triage, exports and users is audited |
| Rendered content | Log text interpreted as HTML/JS | Django autoescape; reports rendered as escaped `<pre>` with `default-src 'none'`; no `|safe` on data |
| Model artifacts | Arbitrary code execution via deserialization, tampered/mismatched model | No upload or path input for models; load only by registry id from `.local/models`; path containment; `.skops` only; SHA-256 match; HMAC with the integrity key; dependency major.minor match; skops untrusted-type audit against a one-type allowlist (`sklearn.tree._tree.Tree`); type and `n_features_in_` checks. A pickle disguised as `.skops` is rejected (tested) |
| Lab driver | Traffic to unintended targets | Driver only accepts fixture-relative paths, then checks that host = 127.0.0.1 and port = the fixture this run started; fixture refuses non-loopback binds outside containers; fake accounts only |
| Exports / publishing | Leaking private data or secrets | Private reports stay in `.local/reports`; public drafts alias entities/sources and omit events; `publish_check` scans Git-visible files; nothing is staged or pushed by the tool |
| Logs of this app | Echoing secrets in errors | Redacting log filter; job errors scrubbed before storage |

## What the integrity check does not prove

The HMAC protects against:

- an artifact or DB row modified on its own;
- loading a file that the pipeline did not create.

It does not protect against an attacker who controls the key file, the DB and the artifact
directory together. Such an attacker can forge a "valid" model. Keep `.local/` on a disk only you
can access, and back up keys separately. The same caveat applies to every hash stored in the same
DB as the data.

## Out of scope / not claimed

- Production hardening, multi-tenant isolation, TLS termination. `production_template.py` is a
  starting point only.
- Detecting skilled or low-volume attackers.
- Any form of automated response.
- On Windows, `chmod 600` on key files has no effect. Rely on the user-profile ACL of the project
  folder.
