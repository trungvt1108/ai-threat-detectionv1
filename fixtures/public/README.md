# Public synthetic fixtures

Hand-written, synthetic sample records (provenance `SYNTHETIC_DEMO`, privacy `DEMO`).

- All IPs are RFC 5737 documentation addresses.
- Host names are `.invalid` or fixture labels.
- The Suricata signature id `9000001` and its text are invented. They are not a real rule.

| File | Purpose |
|---|---|
| `eve_sample.ndjson` | Suricata EVE subset in the 7.0 field layout. Contents: two `alert` events, one `flow` event and one `dns` event (the dns event is unsupported and gets counted). Some records carry a `payload` field that the importer must drop. |
| `nginx_access_sample.txt` | 4 hours of nginx/Apache "combined" lines with a trailing `rt=` duration (`http_combined`). Six normal clients, one path scan by `203.0.113.50` around 02:40 UTC, one malformed TLS probe. Deterministic (fixed seed). |
| `auth_sshd_sample.txt` | 4 hours of `auth.log` lines in RFC 3339 format (`auth_syslog`). Three normal users, CRON noise (skipped), a password-guessing burst by `203.0.113.66` around 01:30 UTC that ends in a successful login, and one rsyslog `message repeated` line. |

To use one, copy the file into an allowed source root (for example `.local/inbox/eve-demo/`) and
register a source of the matching type. See `docs/SOURCES_AND_SCHEMAS.md`.
