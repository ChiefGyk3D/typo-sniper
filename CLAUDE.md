# CLAUDE.md

Guidance for AI assistants (and new contributors) working in this repository.

## What this project is

Typo Sniper is an async Python CLI that detects and monitors typosquatting
domains: it generates permutations of monitored domains (dnstwist plus its own
combo-squat / sound-alike / IDN-homograph generators), enriches the registered
ones (RDAP-first registration data with WHOIS fallback, DNS, SPF/DKIM/DMARC
mail posture, Certificate Transparency, URLScan, HTTP/TLS probing, page
analysis), scores them deterministically, diffs against the previous scan, and
reports/alerts on what changed.

- Package: `src/typo_sniper/`, console script `typo-sniper`, entry point
  `typo_sniper.cli:run`, `python -m typo_sniper` also works.
- Python ≥ 3.10. Licensed AGPL-3.0-or-later, dual-licensed commercially
  (COMMERCIAL.md). SPDX headers are present in source files — keep them.

## Two design rules that must never be violated

1. **The AI and ML layers explain and rank. They never score.** Risk scores
   come only from `calculate_risk_score()` in `threat_intelligence.py` and
   must be identical with AI/ML disabled. A takedown request has to rest on
   evidence a registrar can reproduce.
2. **A failed lookup is never reported as a finding.** Timeouts yield
   `unknown` (scores zero, labelled "Lookup failed"), truncated page parses
   are marked truncated. Never conflate "we couldn't check" with "not there".

Two more conventions with the same force:

3. **Scan data is hostile input.** Domain names, WHOIS registrant fields, page
   titles, and page bodies are attacker-authored. They are sanitised before
   spreadsheets (formula injection), HTML reports (XSS), chat messages
   (markup forgery), AI prompts (injection — see `ai/prompts.py`), and logs.
   Preserve that in any new output path. The `webhook` channel is the one
   deliberate exception (machine consumer).
4. **Secrets are never printed, logged, or written back to disk.** Only key
   names and backend names appear in diagnostics (`--secrets-check`), and
   `Config.save()` strips every field in `Config.SECRET_FIELDS`. Webhook URLs
   count as secrets (the URL *is* the token) — see `BaseNotifier._redact`.

## Commands

```bash
pip install -e ".[dev,ml]"        # dev install
pytest                            # unit tests: hermetic, no network, fast
ruff check src/ tests/            # lint (CI-blocking)
ruff format --check src/ tests/   # formatting (advisory in CI)
typo-sniper --version             # smoke test
```

CI (`.github/workflows/ci.yml`): lint, tests on Python 3.10–3.13, CLI smoke
test, config.yaml.example load check, Docker build. The ruff version comes
from `requirements-dev.txt` — that file is the single source for the pin.

## Testing rules

- `tests/unit/` must stay **hermetic**: no network, no real DNS, no real
  WHOIS. The HTTP-probe SSRF guard does real `getaddrinfo` — tests stub
  `_host_is_public` (see `test_threat_intelligence.py`) or use IP literals.
- `tests/scripts/` are manual walkthroughs that need keys/network; they are
  not run in CI.
- Every bug fix gets a regression test that states the failure it prevents in
  its docstring. Follow the existing style: plain-language docstrings that
  explain *why*, class-per-behaviour grouping.

## Configuration precedence (do not regress this)

Config file / `TYPO_SNIPER_*` env values must survive unless a CLI flag was
explicitly passed. Argparse defaults for overridable settings are `None` in
`parse_arguments()`, and `main()` applies them conditionally. If you add a
CLI flag that mirrors a config field, follow that pattern — a non-None
argparse default silently clobbers the config file.

Secrets resolve through `secrets_manager.py` in this order: env → Doppler →
AWS → Vault → Azure → GCP → 1Password → config file. Doppler and Vault use
plain HTTPS (no SDK); AWS/Azure/GCP/1Password import lazily.

## Versioning and releases

- `src/typo_sniper/version.py` is the **single source of truth**. The README
  version badge (line ~14) is the one other place a version literal lives —
  update it when bumping. Do not add version literals to Dockerfiles, compose
  files, or docs; the release workflow stamps images from the git tag.
- Every release gets a CHANGELOG.md entry (Keep a Changelog format).
- Releases are cut by pushing a `v*` tag; `release.yml` verifies tag ==
  packaged version, publishes to PyPI (Trusted Publishing) and GHCR.

## Screenshots and sample outputs — refresh policy

`media/screen1.png` (the README hero image) is a **function screenshot** of
the HTML report, and `results/sample.{json,csv,html,xlsx}` are committed real
scan outputs. Whenever a change alters report output in any visible way (new
columns, layout, scoring display), regenerate both **after confirming the
feature works** and commit them with the change:

```bash
scripts/refresh_samples.sh          # scans eff.org, rewrites samples,
                                    # re-renders media/screen1.png (1400x953)
```

Requires unrestricted outbound network and a Chromium binary. Never replace
the screenshot with a mock-up; it must show real output of the current code.
Decorative images (the "Enhance!" GIF, badges) are not screenshots — leave
them alone.

## Gotchas

- `dnspython` is a hard requirement even though imports of it are indirect:
  without it dnstwist silently degrades (no MX/NS records, mxcheck no-ops).
- `requirements.txt` pins exact versions (Docker/CI reproducibility);
  `pyproject.toml` uses ranges (PyPI coexistence). Keep both in sync when
  adding a dependency.
- scikit-learn is needed only to *train* the ranking model; scoring is pure
  Python reading a JSON model. Nothing may ever unpickle a model file.
- Page parsing uses only the stdlib `HTMLParser` on purpose (small attack
  surface); do not introduce a third-party HTML parser there.
- WHOIS timeouts rely on `socket.setdefaulttimeout()` being set once,
  process-wide (`scanner._whois_query`). Do not reintroduce a
  save/set/restore pattern around it — that raced across worker threads.
- State files (`state.py`, `ml/labels.py`) are written atomically
  (tmp + `os.replace`). Keep any new persistence the same way; a truncated
  history file silently re-baselines change detection.
- The HTTP probe follows redirects manually so every hop passes the
  private-address guard. Don't switch back to `allow_redirects=True`.
- `results/` and `media/` contents are committed artifacts, not scratch
  space; scan outputs land in timestamped files that are gitignored.

## Documentation map

| Audience | Where |
|---|---|
| End users | README.md (overview), docs/guides/QUICKSTART.md, TESTING.md |
| Feature guides | docs/guides/ (AI, ML, alerting, secrets, debug, API keys) |
| Deployment | docker/DOCKER.md, infra/README.md (Terraform) |
| Verification status | docs/STATUS.md — what's been tested against real services |
| Contributors | CONTRIBUTING.md, PROJECT_STRUCTURE.md, this file |

When adding a feature: update the README feature table, the CLI options
tables (generated from the real parser — keep them honest), the relevant
guide, config.yaml.example (both copies: root and docs/), CHANGELOG.md, and
docs/STATUS.md's verification table.
