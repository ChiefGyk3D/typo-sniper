# Contributing to Typo Sniper

Contributions are welcome — bug reports, detection improvements, new exporters
and notifiers, documentation, and test coverage all help.

## Licensing of contributions

Typo Sniper is [dual-licensed](COMMERCIAL.md): GNU AGPL v3 for everyone, plus a
commercial licence for organisations that cannot meet the AGPL's
source-disclosure terms.

For that model to work, the maintainer has to be able to offer *the whole
codebase* under both licences. If a contribution were AGPL-only, it could never
be included in a commercial licence, and the project would have to either
reimplement it or carry two diverging codebases.

**By opening a pull request you agree that:**

1. You wrote the contribution, or otherwise have the right to submit it under
   these terms.
2. You license it under the AGPL v3, and
3. You grant the maintainer permission to also distribute it under the
   project's commercial licence.

You keep the copyright to your work. This is permission to relicense, not a
transfer of ownership.

Sign off your commits to record this:

```bash
git commit -s -m "Your message"
```

which appends a `Signed-off-by:` line asserting the
[Developer Certificate of Origin](https://developercertificate.org/).

If your employer owns your work output, get their sign-off before contributing.

## Development setup

```bash
git clone https://github.com/ChiefGyk3D/typo-sniper.git
cd typo-sniper
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Before you open a pull request

```bash
pytest                      # full suite, no network access required
ruff check src/ tests/      # lint
```

Both run in CI across Python 3.10–3.13, alongside a CLI smoke test, a Docker
build, `pip-audit`, and CodeQL.

## What good contributions look like

**Tests are not optional.** This is security tooling: a false negative means a
phishing domain goes unreported, and a false positive wastes an analyst's
afternoon. Every behavioural change needs a test that would fail without it.

**Treat scanned data as hostile.** Domain names, WHOIS registrant fields, and
page titles are written by the people being investigated. Anything that reaches
a report, an alert, a log, or a model prompt must be escaped or neutralised for
its destination. There is prior art in `exporters.py` and `notifiers.py`; the
tests there assert it in both directions.

**Prefer transports that work everywhere.** Registration lookups moved from
WHOIS to RDAP because TCP/43 is blocked on many corporate networks and fails as
a silent timeout. New integrations should degrade visibly, not quietly.

**Explain *why* in comments, not *what*.** The code says what it does. Comments
should capture the reasoning that is not recoverable from reading it.

## Reporting security issues

Please do **not** open a public issue for a vulnerability in Typo Sniper itself.
Use [GitHub's private advisory
reporting](https://github.com/ChiefGyk3D/typo-sniper/security/advisories/new),
or contact the maintainer via
[links.chiefgyk3d.com](https://links.chiefgyk3d.com/socials).

Findings *produced by* the tool about third-party domains are ordinary output,
not vulnerabilities in the project.
