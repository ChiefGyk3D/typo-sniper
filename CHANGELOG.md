# Changelog

All notable changes to Typo Sniper are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-08-28

A hardening and correctness release driven by a full adversarial review of the
codebase, plus a documentation and sample refresh. 28 new regression tests
cover every fix (662 total).

### Security

- **The HTTP probe now refuses private and reserved addresses.** A lookalike's
  A record is controlled by whoever registered it. Pointing it at
  `169.254.169.254` or an internal host would previously have the scanner —
  typically run inside the defended network — fetch that address and put the
  response into the report (and, with `--ai`, forward it to a model provider).
  Every redirect hop is now resolved and checked, not just the first URL.
  Operators deliberately scanning internal names can set
  `http_allow_private: true`.
- **Webhook URLs no longer leak into logs.** For Slack, Discord, and the
  generic webhook channel the URL *is* the credential, and aiohttp exception
  messages can quote the full request URL. Delivery errors now log the
  exception type with the URL redacted.
- **`Config.save()` no longer persists resolved secrets.** By the time it
  runs, `resolve_secrets()` may have pulled tokens out of Vault, AWS, or
  1Password; writing them back out as cleartext YAML defeated the point of
  using a secrets backend. All `SECRET_FIELDS` are now excluded.
- **URLScan search queries are URL-encoded**, closing the gap where an IDN
  permutation could alter the query string. The CT lookup already did this.

### Fixed

- **Config file settings are no longer silently overwritten by CLI defaults.**
  `max_workers`, `cache_ttl`, `use_cache`, `months_filter`, and `output_dir`
  set in a YAML config (or via `TYPO_SNIPER_*` environment variables) were
  discarded because the argparse defaults unconditionally replaced them. CLI
  flags now override only when actually passed, and `output_dir` — documented
  since it existed but never read — now works.
- **A scan no longer fails on every domain when URLScan is enabled without an
  API key.** Validation raising inside `__aenter__` meant `__aexit__` never
  ran, leaking one aiohttp session per scanned domain on top of the failure.
- **The Excel export no longer aborts on multi-valued WHOIS fields.**
  python-whois returns a list whenever a field matches more than one value
  (routine when registry and registrar responses are concatenated); a bare
  list in registrant/org/registrar/country cells raised and cost the whole
  workbook.
- **A self-closing `<script/>` no longer blanks page-text analysis.** The
  suppression counter was incremented with no matching end tag, so a
  one-character addition to a phishing page silenced brand-mention detection
  for the rest of the document.
- **WHOIS lookups no longer race on the global socket timeout.** The
  save/set/restore pattern around each query could strip a concurrent
  lookup's timeout entirely — exactly the indefinite hang it existed to
  prevent. The timeout is now set once, process-wide.
- **Scan history and training labels are written atomically**
  (write-then-rename). A crash mid-write — very reachable in watch mode —
  used to truncate the file, silently re-baseline the diff, and suppress
  change detection for that domain forever after.
- **Learned-ranking features are no longer skewed between training and
  scoring.** `has_password_input`, `form_count`, and `brand_mentioned` were
  never persisted in history snapshots, so training always saw zeros for
  them while live scoring saw real values. Snapshots now carry all page
  signals.
- **`ml_min_labels` is honoured in both directions.** Setting it below 30
  previously did nothing: the hardcoded floor was checked first. The
  per-class minimum of 8 still applies.
- **Watch-mode AI token accounting is per-cycle.** The "AI tokens" line
  reported the run-to-date total as if it were the current scan's spend.
- **Unknown configuration keys are now reported** instead of silently
  ignored, so a typo like `enable_url_scan:` no longer runs the scan with
  defaults while the operator believes the feature is on.
- **`pip install "typo-sniper[all]"` can now train the ranking model** —
  the `all` extra was missing scikit-learn while `ai-all` had it.
- **CI lints with the same ruff version developers install.** The workflow
  pinned one version while requirements-dev.txt pinned another; the pin now
  has a single source.

### Changed

- **Version strings are no longer hardcoded where they can go stale.** The
  Docker guides and compose files tag local builds `typo-sniper:latest`, and
  the stale `org.opencontainers.image.version="1.1.0"` labels are gone — the
  release workflow stamps the real version from the git tag.
- `config.yaml.example` corrected: `notify_channels` lists all seven
  channels, `ai_min_risk_score` documents the real default (30), `ai_effort`
  documents `xhigh`/`max`, and `urlscan_visibility` now warns that `public`
  submissions publish your monitored brand list to the URLScan feed.
- **Refreshed the sample reports and README screenshot** to the current
  14-column format (mail posture, page analysis, TLS, age), regenerated
  through the current exporters. `scripts/refresh_samples.sh` now documents
  and automates the process; regenerate whenever report output changes.

## [2.2.1] - 2026-08-27

Documentation catch-up. The feature list had not been touched since 1.1.0 while
a dozen features landed behind it.

### Added

- **[docs/STATUS.md](docs/STATUS.md)** — an honest account of what has been
  verified against real services and what has only ever run against tests and
  stubs, with specific things to try and what to report.

  Every feature has tests and the suite is hermetic, but a passing stub test
  proves the code does what its author expected, not that a vendor's API
  agrees. Several integrations have never had a request leave a developer's
  machine: all six remote secrets backends, every AI provider, Teams, Matrix,
  Jira, and the Terraform modules. The learned ranking model cannot be
  evaluated by anyone yet, because it has no real labels.

- A **Testing and Feedback Wanted** section at the top of the README pointing
  at it, calling out the two highest-value asks: AWS Secrets Manager
  (issue #5), and Jira against a scratch project, since it creates state.

### Changed

- **Rewrote the README feature list.** It described the tool as of 1.1.0 and
  omitted change detection, notifications, ticketing, RDAP, mail intelligence,
  the Public Suffix List, AI triage, learned ranking, page analysis, secrets
  backends, and deployment. Added a summary table, a section on the signals
  that indicate intent, and the two rules that govern the whole design: the AI
  and ML layers explain and rank but never score, and a failed lookup is never
  reported as a finding.

- **Rebuilt the CLI options tables** from the actual parser, grouped by task.
  Fourteen flags were missing, including every flag for monitoring, alerting,
  AI, and learned ranking.

- **Regenerated the project structure tree**, which still showed the pre-2.0.0
  flat module layout.

### Fixed

- **Seven broken documentation links**, including two pointing at a guide that
  never existed and four using paths relative to the repository root from files
  inside `docs/guides/`. Verified by a link check across every Markdown file.

## [2.2.0] - 2026-08-27

### Added

- **Terraform / OpenTofu modules** for running Typo Sniper as a scheduled
  scanner on AWS, in `infra/terraform/`: a Fargate task driven by EventBridge
  Scheduler, a Kubernetes CronJob for teams already on EKS, and a shared module
  holding the S3 reports bucket, EFS state, Secrets Manager secret, and
  security groups both use. Working examples for each.

- **boto3 and a report uploader in the container image.** The image is how
  people run this on AWS, and both the Secrets Manager backend and shipping
  reports to S3 need a client. `typo-sniper-upload` sends a finished scan's
  reports to `RESULTS_BUCKET`, and is inert when that variable is unset.

- **`TYPO_SNIPER_STATE_DIR`, `TYPO_SNIPER_OUTPUT_DIR` and
  `TYPO_SNIPER_CACHE_DIR`.** A container image ships a default and the
  deployment redirects it, so for these three the environment wins — unlike
  credentials, where an explicit config value is a deliberate act and takes
  precedence.

### Fixed

- **A containerised deployment could silently stop detecting changes.** The
  scan history that every delta is computed against lives in `state_dir`, which
  had no environment override, so a container had no way to point it at a
  persistent volume without a config file baked into the image. On ephemeral
  storage every scheduled run looks like a first run: no deltas, no alerts, and
  a scanner that appears to work perfectly while doing none of the job it was
  deployed for. Nothing errors and nothing warns, which is what makes it worth
  calling out.

  Found while writing the IaC — the Terraform set the variable and the
  application ignored it.

- **The container image had no AWS client**, so on AWS the documented Secrets
  Manager backend resolved nothing and the scan ran with no API keys at all,
  reporting no error. Weighing the megabytes against a scanner that quietly
  runs unauthenticated, the megabytes lose.

- **`.dockerignore` excluded `docker/`**, which would have broken the image
  build once the uploader was copied in — the same way it excluded
  `pyproject.toml` in 2.0.0. Caught this time by building the context before
  pushing rather than after CI failed.

## [2.1.0] - 2026-08-27

The scanner can now see what a suspicious page is built to *do*, not just that
it exists.

### Added

- **Credential-form detection.** A registered lookalike tells you someone
  bought a domain. A lookalike serving a form with a password field tells you
  what they bought it for. That is the difference between a finding worth
  watching and one worth a takedown request this afternoon, and until now the
  scanner could not see it — it read the page title and nothing else.

  The HTTP probe already read the page body to extract `<title>`, so this costs
  **no extra request**. It reports whether the page collects a password,
  whether it pairs that with a username or email field, how many forms it has,
  and whether the page names the brand it is imitating.

  A `type="text"` field named `passwd`, `otp`, `cvv` or `card_number` counts:
  changing the input type is a one-character edit, and the field name gives the
  intent away.

- **Off-site form actions.** A form on `examp1e.com` that POSTs to
  `collector.evil.test` is an exfiltration path, not a login page. Comparison
  is by registrable domain via the Public Suffix List, so `login.examp1e.com`
  is correctly *not* flagged as off-site.

- **A credential form appearing now raises an `ESCALATED` change.** That
  transition — a parked lookalike becoming a live collection point — is the
  most actionable thing this tool can report, and it is now persisted in scan
  history so the diff engine can see it. So is a form that starts submitting
  off-site.

- **Five new ML features** and new evidence lines in the AI prompt, both
  drawn from the same analysis. The page findings are derived by our own
  parser from the fetched markup rather than copied from attacker-supplied
  text, which makes them the most trustworthy lines in the prompt's data block.

- **A `Page` column** in the CSV, Excel, and HTML reports.

### Changed

- **Risk scoring is weighted so page findings dominate**, which they should: a
  credential form adds 30, an off-site form action 15, and a brand mention 10
  — but only alongside something that actually collects. A fan page naming a
  brand is not a phishing kit, and scoring it like one would train operators to
  ignore the signal.

- **The feature set changed, so previously trained ranking models are
  refused** with a message to retrain, rather than silently scoring a
  mismatched vector. That guard was added in 1.5.0 for exactly this case.

### Security

- **Parsing uses the standard library's `HTMLParser`, not a third-party
  parser.** This is attacker-authored markup by definition, so the smaller and
  more boring the parsing surface, the better: no external entity resolution,
  no network fetches, no recovery heuristics that could be steered.

- **Every collection is bounded** — forms, inputs, and text — because a page
  designed to be parsed slowly is a cheap way to stall a scan. The body was
  already capped at `http_max_bytes`.

- **A page that breaks the parser is reported as truncated**, not as a clean
  reading. "No password field found" and "we stopped looking" are different
  claims, and the AI prompt says which one it is.
## [2.0.0] - 2026-08-27

Typo Sniper is now installable. `pip install typo-sniper` gets you a
`typo-sniper` command, and there is a container image on GHCR.

The major version is because the way you invoke it changed. See **Migrating**
below; it is a one-line change.

### Breaking

- **`python src/typo_sniper.py` no longer exists.** The code moved into a real
  `typo_sniper` package under `src/`, so the entry points are now:

  | Before | Now |
  |---|---|
  | `python src/typo_sniper.py -i domains.txt` | `typo-sniper -i domains.txt` |
  | — | `python -m typo_sniper -i domains.txt` |

  Update any cron entry, systemd unit, or CI step that called the script path.

- **The Docker image's entrypoint is now the installed console script** rather
  than a loose copy of the modules. Arguments are unchanged, so
  `docker run ... typo-sniper:tag -i domains.txt` works as it did.

### Added

- **PyPI packaging.** `pip install typo-sniper`, with optional extras for AI
  providers (`[claude]`, `[openai]`, `[gemini]`, `[ai-all]`), model training
  (`[ml]`), and secrets backends (`[aws]`, `[azure]`, `[gcp]`,
  `[secrets-all]`), or `[all]`.

- **A release workflow** publishing on a version tag: a multi-architecture
  image (amd64 and arm64) to GHCR with build provenance and an SBOM, and a
  distribution to PyPI via **Trusted Publishing**. There is no long-lived PyPI
  token stored in this repository to leak; the credential is minted per run and
  scoped to this workflow.

  The workflow refuses to publish when the git tag disagrees with the packaged
  version, because an artifact whose version cannot be traced back to a commit
  is worse than no artifact.

- **`python -m typo_sniper`** as an entry point alongside the console script.

### Fixed

Packaging that had been quietly broken. All three were found by actually
building and installing the thing rather than by reading the config:

- **`pyproject.toml` had no `[build-system]` and no package discovery.** An
  install "succeeded" and produced something unusable: `import typo_sniper`
  resolved to the CLI script, which then died on its own sibling imports.

- **The package reported `Version: 0.0.0`.** `dynamic = ["version"]` was
  declared with nothing configured to resolve it, so setuptools fell back to a
  placeholder. The version now comes from `typo_sniper.version.__version__`,
  and CI checks it against the release tag.

- **No runtime dependencies were declared at all.** A `pip install` of the
  distribution would have fetched the code and none of the libraries it needs.
  `pyproject.toml` now lists them as ranges; `requirements.txt` keeps its exact
  pins, which is where reproducibility actually matters — the Docker image and
  CI.

- **Flat modules would have polluted the top-level namespace.** Publishing this
  as it stood would have put `config`, `utils`, `cache`, `state`, `scanner` and
  friends directly into every installing user's `site-packages`, colliding with
  anything else that owns those names. The release workflow now asserts that
  none of them are importable after install.

### Migrating

```bash
pip install -e .           # from a clone; or pip install typo-sniper

# then, wherever you had:
#   python src/typo_sniper.py -i domains.txt
# use:
typo-sniper -i domains.txt
```

Config files, state directories, cached data, trained models, and labels are
all unchanged and need no migration.

## [1.6.0] - 2026-08-27

Completes the alerting channels, and adds ticketing as something distinct from
alerting.

### Added

- **Microsoft Teams** alerts, as an Adaptive Card sent to a Power Automate
  "When a Teams webhook request is received" trigger. That is the current path:
  the older Office 365 connector, which took a MessageCard at an
  `outlook.office.com` URL, has been retired by Microsoft.

- **Matrix** alerts via the client-server API, with no SDK required. Two
  details that matter: the access token is sent as a bearer header rather than
  the deprecated `?access_token=` query parameter, which would put the
  credential in the homeserver's request logs and in every proxy along the way;
  and each send carries a fresh transaction ID, so a retried delivery is
  idempotent at the homeserver instead of double-posting.

- **Jira ticketing.** This is not another chat channel, and the difference
  drives its design. A message is disposable; a ticket is state, and a
  scheduled scan that opened a fresh ticket for the same lookalike every
  morning would bury a queue within a week. So:

  - **One issue per domain, not per scan.** A lookalike is tracked from
    detection through takedown, which is the unit of work an analyst has.
  - **Deduplicated by a deterministic label.** The project is searched for an
    open issue carrying this domain's label before anything is created. A
    closed issue stays closed — a domain that comes back raises a new ticket,
    which is correct, because it genuinely is a new event.
  - **Capped per run** (`jira_max_issues_per_run`, default 10). The first scan
    of a well-known brand can surface hundreds of registered lookalikes, and
    turning that into hundreds of tickets would be the most destructive thing
    this tool could do to someone's backlog. What the cap drops is logged, and
    stays in the report and the delta JSON.

  Only new, escalated, and activated findings are ticketed. A resolved domain
  is good news, not work.

### Changed

- Notifiers now share one request helper supporting any HTTP method and custom
  headers, so Slack's POST and Matrix's PUT go through the same timeout,
  error-handling, and logging path. `WebhookNotifier` keeps its own call
  deliberately, because it sends operator-supplied headers verbatim.

- Teams, Matrix, and Jira credentials resolve through the secrets backends like
  every other credential, so none of them need to sit in `config.yaml`.

### Fixed

- **`aiohttp.BasicAuth` is deprecated and removed in aiohttp 4.0.** The Jira
  Basic header is now built with the standard library, which works on every
  aiohttp version and adds no dependency. Caught by running the notifier tests
  with `-W error::DeprecationWarning` rather than by waiting for aiohttp 4.

## [1.5.0] - 2026-08-27

Learned triage: the tool starts using your own past decisions to order what it
shows you.

### Added

- **Learned triage ranking (`--ml-rank`).** The risk score orders findings by a
  formula that is identical for everyone, but teams differ in what they act on:
  a bank cares most about mail capability, a consumer SaaS about a cloned login
  page. This learns that difference from the operator's own judgements and
  reorders accordingly.

  **The model ranks; it never scores.** Risk scores are unchanged whether this
  is on or off and remain the number cited in takedown requests — the same rule
  the AI layer follows, for the same reason. A registrar can check "registered
  nine days ago, valid SPF and DKIM, serving a login page." It cannot check
  "our model put it first."

- **Operator labelling (`--label DOMAIN=acted|dismissed`).** Records the
  decisions that become training data. `dismissed` is treated as first-class
  and training refuses without it: a model trained only on confirmed-bad
  examples learns that everything is bad.

- **`--ml-train` and `--ml-status`.** Training reports a cross-validated ROC
  AUC rather than a training score, since on a forty-label set the difference
  between those two numbers is the whole story. It refuses below 30 labels and
  8 of each class, because below that a model fits noise, and a confidently
  wrong ranking is worse than no ranking — it looks like signal.

- **34 deterministic features**, all traceable to a field a human can look at:
  lexical, relational (edit distance to the brand, scaled by brand length), DNS,
  registration age, mail posture, TLS validity, page content, and the
  deterministic risk score itself. The risk score is included as a feature
  rather than replaced: it encodes expert judgement that forty labels cannot
  rediscover, so the model starts from it and learns adjustments.

### Security

- **Model files are JSON and are never unpickled.** `pickle.load` on a model
  file is arbitrary code execution, and model files get emailed between
  colleagues and committed to repositories. The trained model is stored as
  feature names, weights, intercept, and standardisation constants; scoring is
  a dot product and a sigmoid in pure Python.

  This is why the model is logistic regression rather than a boosted ensemble
  that would likely score a point or two higher: an opaque model would trade
  away both the explanation and the safety property, to reorder a list a human
  reads either way.

- **Training needs scikit-learn; scoring does not.** Hosts that run scans
  install nothing. Only whoever trains needs `.[ml]`.

### Fixed

- **Training features come from the earliest snapshot of a domain, not the
  newest.** A domain that was successfully taken down resolves nowhere today.
  Matching labels to current state would have taught the model that dead
  domains are the dangerous ones — an inversion of the truth, learned from
  perfectly good labels, that would rank every parked domain above every live
  one.

- **The risk-score feature is clamped, not just scaled.** An out-of-range value
  from a stale record would otherwise dominate every weight in a linear model.
  Caught by a bounds test over the whole feature vector.

- **A stale model is refused rather than used.** If features are added or
  reordered after training, the stored model no longer matches the vector it
  would be scoring; it is rejected with a message to retrain instead of
  silently producing plausible nonsense.

## [1.4.0] - 2026-08-27

AI-assisted triage, and secrets management that is actually wired in.

### Added

- **AI-assisted triage (`--ai`).** A scan of a well-known brand returns hundreds
  of registered permutations; risk scores rank them but do not explain them.
  This reads the signals together and says what they suggest about intent, which
  findings are load-bearing, and what the next step would be. Four backends:
  Claude, OpenAI, Gemini, and Ollama.

  **The model explains, it never scores.** Risk scores stay deterministic and
  identical with AI off, because a takedown request has to rest on reproducible
  evidence. The system prompt forbids scoring, the response schema has no score
  field, and `additionalProperties: false` means a steered model fails
  validation rather than quietly landing a number in a report.

  **Ollama is a first-class option, not a footnote.** A scan's output names the
  domains an organisation is defending, which reveals what they own and what
  they are worried about. For teams that cannot send that to a third party, a
  local model is the difference between using this feature and disabling it.

- **Prompt-injection defences.** Every field the model sees about a suspicious
  domain — the name, the WHOIS registrant and organisation, the page title —
  was written by the person who registered it, and a registrant field is a free
  text box that costs nothing to fill with an instruction. Untrusted values
  never enter the system prompt; they are fenced inside delimiters the data
  cannot reproduce, stripped of control characters, collapsed to a single line,
  truncated, and schema-constrained, and any assessment naming a domain that
  was not in the request is discarded.

  An injection attempt is **marked, not deleted**: the text stays visible and
  the finding is surfaced, because a registrant field carrying an instruction
  aimed at an automated analyst is itself evidence of intent.

- **Secrets backends: HashiCorp Vault, Azure Key Vault, Google Cloud Secret
  Manager, and 1Password**, joining environment variables, Doppler, and AWS
  Secrets Manager. Doppler and Vault are reached over HTTPS with the standard
  library, so the two most commonly self-hosted stores need nothing installed.
  Backend order is configurable via `secrets_backends`.

- **`--secrets-check`.** Reports which backends are reachable and where each
  credential resolved from, and never prints a value. Debugging a missing key
  with `echo` puts the value in shell history; this exists so that is never the
  first thing reached for.

### Fixed

- **Secrets managers were advertised but never used.** `SecretsManager` existed
  and was documented, but nothing called it: `Config` read `os.getenv` directly,
  so a key stored in Doppler or AWS was only ever found when it happened to
  already be an environment variable. Every credential field now resolves
  through the backend chain. A value set explicitly in `config.yaml` still wins,
  since an explicit setting must not be overridden by a stale vault entry.

- **A failing secrets backend no longer takes the run with it.** An unreachable
  store is passed over and the next backend is tried. Backend errors record only
  the exception type, never its message, because a store's error text can echo
  the request body, the token, or the secret itself into a log.

- **The `op` binary is resolved to an absolute path** rather than relying on
  PATH order at call time, and is run without a shell.

### Changed

- `env` is always consulted first and is re-inserted if omitted from
  `secrets_backends`. Overriding one key for one run must never require editing
  a vault the whole team shares.
- Optional dependencies are now extras: `.[claude]`, `.[openai]`, `.[gemini]`,
  `.[ai-all]`, `.[aws]`, `.[azure]`, `.[gcp]`, `.[secrets-all]`, `.[all]`.

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
