# Feature Status: What's Verified, What Needs Your Testing

Typo Sniper gained a lot of surface area quickly. This page is an honest
account of what has been exercised against real services and what has only ever
run against tests and stubs.

**Nothing here is known-broken.** Every feature has automated tests, and the
suite is hermetic — a fixture fails any test that opens a socket to anything but
localhost. But a passing stub test proves the code does what its author
expected, not that a vendor's API agrees. The gap between those two is where
this list lives, and closing it needs people with real accounts and real
domains.

If you try something below, **please open an issue either way** — "this worked
exactly as documented" is as useful a data point as a bug report, and much
rarer.

---

## Fully verified

Exercised end to end, against real data, with no external account required.

| Feature | Since | How it was verified |
|---|---|---|
| dnstwist detection, combo-squat, sound-alike, IDN | 1.0 | Unit tests, real scans |
| Public Suffix List domain splitting | 1.3.0 | Unit tests over multi-label suffixes |
| DNS resolution, mail posture (SPF/DKIM/DMARC) | 1.3.0 | Real DNS, including TCP retry for large TXT |
| Change detection and diffing | 1.2.0 | Round-trip tests over recorded history |
| Risk scoring | 1.1.0 | Unit tests per signal and combination |
| Page analysis / credential forms | 2.1.0 | Fixture HTML, incl. malformed and hostile input |
| Report exports (Excel, JSON, CSV, HTML) | 1.0 | Generated and opened |
| Packaging: build, install, console script | 2.0.0 | Built and installed into clean 3.10 / 3.11 venvs |
| Prompt-injection defences | 1.4.0 | Adversarial fixtures; 0 markers escaped |
| HTTP probe private-address guard (SSRF) | 2.3.0 | Unit tests over loopback/RFC1918/link-local literals and redirect hops |
| Config-file precedence over CLI defaults | 2.3.0 | Regression tests; real scan with a file-configured run |

---

## Needs testing against real services

These have complete implementations and passing tests, but **no request has
ever left a developer's machine to the real endpoint.** Request shapes are
asserted against stubs built from vendor documentation.

### 🔑 Secrets backends — [issue #5](https://github.com/ChiefGyk3D/typo-sniper/issues/5)

| Backend | Status | What would help |
|---|---|---|
| Environment / `.env` | ✅ Verified | — |
| Doppler | ⚠️ Untested live | Does `doppler run` injection resolve? Does the REST path work with a service token? |
| AWS Secrets Manager | ⚠️ Untested live | Does the JSON-blob secret parse? Does an instance profile / IRSA resolve? |
| HashiCorp Vault | ⚠️ Untested live | KV v2 path shape, namespace header, `~/.vault-token` pickup |
| Azure Key Vault | ⚠️ Untested live | Does `DefaultAzureCredential` resolve? Is the dashed name mapping right? |
| GCP Secret Manager | ⚠️ Untested live | Does ADC resolve? Underscore vs dashed secret naming |
| 1Password | ⚠️ Untested live | Does `op read` work for both a signed-in user and a service account? |

Start with `typo-sniper --secrets-check`. It reports which backends are
reachable and where each credential resolved from, and **never prints a value**.

### 🤖 AI providers

No live call has been made to any provider. The request shapes follow current
API documentation, but APIs drift.

- **Claude** — adaptive thinking, streaming, JSON schema output
- **OpenAI** — strict JSON schema mode
- **Gemini** — schema adaptation (it rejects `additionalProperties`)
- **Ollama** — local HTTP, format-constrained

Most useful report: run `--ai` against a small domain list and say whether the
response parsed, whether the assessment was *useful*, and roughly what it cost.

### 🔔 Alert channels

| Channel | Status |
|---|---|
| Slack, Discord | ⚠️ Payload shapes tested, never delivered live |
| Microsoft Teams | ⚠️ Untested. Uses Power Automate — the old O365 connector is retired |
| Matrix | ⚠️ Untested. Check the message renders and the token stays out of logs |
| **Jira** | ⚠️ **Untested, and the highest-risk one** |
| Webhook, email | ⚠️ Untested live |

**Test Jira against a scratch project first.** It creates state: one issue per
domain, deduplicated by label, capped at `jira_max_issues_per_run` (default 10).
The dedupe logic and the cap are both tested, but a wrong JQL or field shape
against a real instance is worth finding on a throwaway project rather than your
security backlog.

### 🧠 Learned triage ranking

**This one cannot be evaluated at all yet, by anyone, including us.**

The plumbing is verified: feature extraction, the training pipeline, the JSON
model format, the refusal of stale models. But whether the model *helps* is
unknowable until it has real labels from real triage decisions.

To generate the first real signal:

```bash
typo-sniper --label suspicious-domain.com=acted
typo-sniper --label harmless-domain.com=dismissed
# ...roughly 30 decisions, at least 8 of each
typo-sniper -i domains.txt --ml-train
typo-sniper -i domains.txt --ml-status
```

An unremarkable ROC AUC around 0.5–0.6 **is a legitimate result**, not a bug: it
means your decisions already track the deterministic risk score and the model
has nothing to add. That finding is worth reporting.

### ☁️ Infrastructure (Terraform / OpenTofu)

Syntax and formatting are checked. **No `plan` or `apply` has ever run**, because
the provider registry is unreachable from the development sandbox — so provider
schemas were never validated and argument names were written from documentation.

Expect to hit at least one argument mismatch on first `tofu plan`. Please report
them; they are cheap to fix and impossible to find without an AWS account.

The design decision most worth a second opinion: **scan state lives on EFS.**
Typo Sniper keeps history in a local directory, so a scheduled container on
ephemeral storage would treat every run as a first run and never report a
change — working perfectly while doing none of the job. EFS is the fix for both
ECS and EKS. If you see a better shape, say so.

### 📦 Publishing

The build and install path is verified. The **upload** steps have never run:
PyPI Trusted Publishing needs a one-time publisher registration, and the GHCR
push happens only on a `v*` tag.

---

## Known limitations

- **No remote state backend.** Scan history is a local directory. Containerised
  deployments need a persistent volume (the Terraform modules mount EFS). An
  S3-backed state store would be a genuine improvement.
- **Page analysis reads only the first `http_max_bytes`** (1 MiB default). A
  credential form past that point is not seen.
- **Brand mention counting is substring-based**, so a short brand name inside a
  longer unrelated word will match.
- **The AI layer sends scan metadata to a third party** unless you use Ollama.
  That metadata names the domains you are defending.

---

## How to report

- **Bugs and live-service results** — [open an issue](https://github.com/ChiefGyk3D/typo-sniper/issues)
- **Something worked as documented** — say so on the relevant issue; confirmation is genuinely valuable
- **Security findings** — open an issue without exploit detail and it will be moved somewhere private to continue
