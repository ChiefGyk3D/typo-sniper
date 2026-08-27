# Changelog

All notable changes to Typo Sniper are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-08-24

Detection quality. Adds the single strongest pre-attack signal a lookalike can
emit, and fixes registrable-domain splitting for most of the world.

### Added

- **Mail-capability intelligence (SPF / DKIM / DMARC).** Registering a lookalike
  is cheap and means little. Provisioning it to send mail that passes receiver
  checks is deliberate work whose only purpose is deliverable mail, which is the
  prerequisite for credential phishing and business email compromise. Domains are
  now classified `none` / `receive-only` / `partial` / `provisioned` / `hardened`,
  reported in a new `Mail` column, and scored accordingly. A squat that gains
  send capability between scans raises an `ESCALATED` change.
- **Public Suffix List** for registrable-domain splitting, replacing the ~40-entry
  hardcoded tuple added in 1.1.0. That list mishandled everything outside it:
  `example.com.br` and `example.github.io` were split wrongly, so generated
  variations pointed at the wrong namespace entirely. `publicsuffixlist` bundles
  its data offline and is released on the PSL's own cadence.
- **Per-brand combo-squatting keywords** (`custom_keywords`). Product names,
  campaign names, and support portals are better bait than the generic list.
  `replace_default_keywords` uses only your terms.

### Fixed

- **A failed DNS lookup is no longer reported as a finding.** Large TXT responses
  need TCP, and the first implementation returned "no SPF" for any domain whose
  response exceeded UDP limits — `google.com` among them. That is the same
  mistake as treating a WHOIS timeout as "no registration date": absence of
  evidence rendered as evidence of absence. Lookups now retry over TCP, and a
  genuine failure yields `unknown`, which scores zero and is labelled
  "Lookup failed" in reports rather than left blank.

### Changed

- Risk scoring uses the full mail assessment where available, replacing the
  earlier MX-only heuristic. MX alone shows a domain can *receive*; SPF shows it
  is provisioned to *send*.

## [1.2.0] - 2026-08-24

Turns a report generator into a monitoring tool. Scans are now diffed against
the previous run, alerts fire on what changed, and registration data comes from
RDAP instead of a port that half the world blocks.

### Added

- **Change detection.** Every scan is compared against the previous one and
  reports lead with the delta: `NEW` registrations, `ESCALATED` risk, sites that
  just went live or gained MX records or a certificate (`ACTIVATED`), ownership
  and hosting `CHANGED`, and squats that `RESOLVED` away. A defender reading a
  daily report wants to know what moved, not to re-read seventy unchanged rows.
  The first scan of a domain establishes a baseline silently rather than
  reporting everything as new.
- **Alerting** to Slack, Discord, a generic JSON webhook, and email
  (`--notify slack discord webhook email`). Alerts fire *only* on changes, so a
  daily schedule stays worth reading. `notify_min_changes` suppresses trivial
  drift. Endpoints are read from the environment as secrets.
- **RDAP registration lookup** (RFC 7482), tried before WHOIS. WHOIS needs
  TCP/43, which is blocked on many corporate networks and in most CI sandboxes,
  where it fails as a silent timeout — during development of the previous
  release every one of 67 lookups failed for exactly this reason. RDAP is HTTPS
  on 443, returns structured JSON with unambiguous timestamps, and shares the
  scanner's existing async session instead of occupying a worker thread. WHOIS
  remains the fallback for registries that publish no RDAP endpoint, and reports
  record which source answered.
- **Watch mode**: `--watch --interval 6h` runs continuously instead of relying
  on the compose file's scheduling comment, which never actually scheduled
  anything. `--interval` accepts `30m`, `6h`, `2d`, or plain seconds.
- `latest_changes.json` written alongside each report for downstream tooling.
- Scan history under `state_dir`, retaining `history_retain` scans per domain.

### Changed

- The CLI summary now reports which lookup source answered, and flags notable
  changes per domain as the scan runs.
- `--no-rdap`, `--no-diff`, and `--notify-min-changes` added for control.

### Security

- Chat notifiers strip markup-significant characters from domain names,
  registrant fields, and page titles, all of which are attacker-controlled — the
  same class of issue fixed in the report exporters in 1.1.0. The JSON webhook
  deliberately sends values verbatim, because a machine consumer correlates on
  the exact domain and JSON encoding already prevents structural injection.
- SMTP failures log the exception type only, never the message body.

## [1.1.0] - 2026-08-21

A correctness and security release. Report output and risk scores from this
version differ from 1.0.3 — see **Changed** before comparing runs.

### Security

- **HTML reports no longer execute attacker-supplied markup.** Domain names,
  WHOIS registrant and organization fields, and probed page titles were
  interpolated into the HTML report without escaping. A typosquatter controls
  their own WHOIS record, so they could place script into a report that an
  analyst then opened. All untrusted values are now HTML-escaped.
- **URLScan report links are scheme-checked.** A `javascript:` or `data:` URL
  arriving in an API response can no longer become a clickable link.
- **CSV and Excel exports are protected against formula injection.** Values
  beginning with `=`, `+`, `-`, `@`, tab, or carriage return are prefixed with a
  quote so spreadsheet applications treat them as text.
- **HTTP probe response bodies are bounded** (1 MiB by default, configurable via
  `http_max_bytes`). Probed hosts are hostile by definition and could previously
  stream an unbounded body into memory. Redirects are also capped, and requests
  now send an identifying User-Agent.
- Added `pip-audit` and CodeQL workflows.
- **HTTP probes always validate TLS certificates.** The outcome is recorded as
  a new `TLS` report column: a lookalike domain presenting a valid certificate
  was set up deliberately, which is intelligence worth keeping rather than
  discarding. A host that answers but fails validation is reported as
  `Invalid/self-signed` and counted as live, and the probe deliberately stops
  there instead of refetching with verification disabled — that body would
  become the page title in an analyst's report, read over a channel just
  proven unauthenticated. Liveness for such hosts is still established by the
  plain HTTP probe.
- **AWS Secrets Manager logging no longer records the exception or the secret
  name.** Messages raised by a secrets backend can embed response content, and
  secret names can reveal internal structure in a shared log aggregator. Only
  the exception type is logged.

### Fixed

- **Unregistered domains were reported as registered.** dnstwist reports
  resolver failures as sentinel strings (`!ServFail`, `!NXDOMAIN`), which the
  registration check treated as addresses. These are now filtered out.
- **`dnspython` was missing from `requirements.txt`.** Without it dnstwist
  silently degrades to socket lookups: no MX or NS records are collected,
  `mxcheck` becomes a no-op, and more permutations resolve to error sentinels.
  Only the Docker image installed it.
- **Registration age never contributed to the risk score.** `calculate_risk_score`
  read a `created_days_ago` field that nothing ever set, so the strongest
  typosquatting signal scored zero.
- **URLScan verdict scores saturated the risk cap.** The 0-100 URLScan score was
  multiplied by 20, so any non-zero verdict pinned the total at 100 and every
  flagged domain looked equally dangerous.
- **"Recent registrations" was always empty** unless `--months` was passed, since
  `is_recent` was only set inside the date filter. Recency is now always computed.
- **The monitored domain itself was counted as a registered permutation**,
  inflating `registered_count` by one in every report.
- **`cache_dir: ~/.typo_sniper/cache` was not expanded**, so the shipped example
  config created a literal `~` directory in the working directory.
- **Configured options were ignored**: `dnstwist_threads`, `dnstwist_mxcheck`,
  `dnstwist_phash`, `whois_timeout`, `whois_retry_count`, `whois_retry_delay`,
  `rate_limit_delay`, and `enable_soundalike` were all documented but unused.
- **WHOIS lookups had no timeout**, so an unresponsive server could hang a
  worker thread indefinitely.
- **A totally failed WHOIS stage was indistinguishable from a clean scan.** The
  run reported success with no warning. WHOIS success/failure counts now appear
  in the summary, the Excel report, and the JSON output.
- `is_homograph()` returned true for any domain containing the letter `l`,
  because the confusable table lists ASCII `l` and `I` as lookalikes for `1`.
- Combo-squatting generated hostnames containing underscores, which are invalid
  in DNS and could never resolve, and mis-parsed multi-label suffixes so
  `example.co.uk` produced variations under `.uk`.
- `SoundAlikeDetector.soundex('')` raised `IndexError`.
- Excel column widths were never computed for numeric columns.
- Page title extraction missed `<title>` tags carrying attributes or newlines.
- `datetime.utcnow()` (deprecated since Python 3.12) replaced with timezone-aware
  equivalents.
- The scanner's thread pool is now shut down on exit.
- An unexpected URLScan search status silently produced "No Scan Available"
  instead of reporting the error.

### Added

- Unit test suite (154 tests, no network required) covering validation, DNS
  sentinel handling, risk scoring, config loading, caching, detection
  algorithms, and export sanitisation.
- GitHub Actions CI: lint, tests on Python 3.10-3.13, CLI smoke test, and a
  Docker build that asserts the image does not run as root.
- Dependabot for pip, GitHub Actions, and Docker.
- `pyproject.toml` with pytest and ruff configuration.
- `recent_days` setting to control the recency window (default 90 days).
- WHOIS circuit breaker: after 10 consecutive failures, retries are abandoned
  for the rest of the run rather than multiplying a systemic outage by the
  retry count.
- Certificate Transparency lookups retry crt.sh's frequent 502/504 responses.
- `Age (days)` and `Organization` columns in the reports.

### Changed

- **Risk scoring rebalanced.** Registration recency and MX capability now carry
  real weight; URLScan's score contributes proportionally rather than
  saturating. Scores are not comparable to 1.0.3 output.
- Minimum supported Python is now 3.10.
- Docker images build with a multi-stage layout (no compiler in the final
  image), run as an unprivileged user, and base on `python:3.13-slim`. The cache
  path moved from `/root/.typo_sniper/cache` to `/home/sniper/.typo_sniper/cache`.
- WHOIS defaults are less patient: 15s timeout, 2 attempts, 2s between them.
- URLScan API keys are validated once per process instead of once per scanned
  domain.
- Dependencies updated: `rich` 14.2.0 → 15.0.0, `aiohttp` 3.13.1 → 3.14.3,
  `python-dotenv` 1.1.1 → 1.2.3.
- Removed `aiofiles` and `whois-parser`, which were pinned but never imported.
- Threat intelligence formatting is shared by all exporters instead of being
  reimplemented three times.
- Obsolete `version:` key removed from Docker Compose files.

## [1.0.3]

- Report generation fixes; URLScan.io result URLs in output.

## [1.0.2]

- Smart URLScan auto-enable, security fixes, VirusTotal integration removed.

## [1.0.0]

- Initial public release.
