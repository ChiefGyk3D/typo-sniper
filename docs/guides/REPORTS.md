# Understanding Scan Results

What every column in a Typo Sniper report means, which signals matter, and
what to do about the findings. Applies to all four formats — Excel, HTML,
CSV, JSON — which are different renderings of the same data.

## The report at a glance

A scan of one monitored domain typically returns dozens of registered
permutations. Most are harmless: parked domains, unrelated businesses whose
name happens to be one edit away, speculators holding a name. The report's
job is to make the handful that represent deliberate targeting stand out.

Findings are ordered by **risk score**. With `--ml-rank` and a trained model,
ordering follows your own past triage decisions instead — the scores
themselves never change.

## Column reference

| Column | Meaning | When to care |
|---|---|---|
| **Domain** | The registered permutation | — |
| **Fuzzer** | How it was generated: `addition`, `replacement`, `homoglyph`, `tld-swap`, `combosquatting`, `soundalike`, … | `homoglyph` and `combosquatting` hits are rarely accidental |
| **Risk** | Deterministic 0–100 score (see below) | 70+ investigate now, 50–69 monitor closely |
| **Age (days)** | Days since WHOIS/RDAP creation date | Under 30 days is the strongest single behavioural signal |
| **Mail** | Mail posture from SPF/DKIM/DMARC: blank → `Receive only (MX)` → `Partial` → `SEND-CAPABLE` → `SEND-CAPABLE (DMARC enforced)`, or `Lookup failed` | SEND-CAPABLE on a lookalike means someone provisioned it to deliver mail that passes receiver checks — the prerequisite for phishing and BEC |
| **Page** | What the served page collects: credential form, password field, off-site form action, brand mention | A credential form **is** the phishing kit. An off-site form action is an exfiltration path |
| **URLScan Status** | URLScan.io verdict with a link to the full report | `Malicious` is near-conclusive; `Clean` only means "not yet flagged" |
| **CT Logs** | Certificates ever issued for the domain | A certificate means someone did deliberate setup work |
| **HTTP Status** | Liveness: `HTTPS: 200`, `HTTP: 404`, `Inactive`, `HTTPS: cert rejected` | A live site outranks a parked one; content matters more than liveness |
| **TLS** | `Valid` or `Invalid/self-signed` | Valid TLS on a lookalike means real effort; invalid TLS on a live host is its own finding |
| **Created / Registrant / Organization** | Registration data via RDAP (WHOIS fallback) | Privacy-proxied registrants are normal; a registrant impersonating your company is not |
| **IP** | A records | Same hosting as previous campaigns, or an address inside your own ranges, are both notable |

Blank cells mean *not checked or not found*; `Lookup failed` /
`http_403`-style statuses mean *checked and could not determine* — the report
never presents a failed lookup as a clean result.

## How the risk score is built

The score is a fixed, reproducible formula (`calculate_risk_score` in
`src/typo_sniper/threat_intelligence.py`) — the same inputs always produce
the same score, with AI and ML features on or off. Strongest components:

- **What the page collects**: credential form +30, bare password field +20,
  form posting to another registrable domain +15, brand mention alongside
  collection +10
- **URLScan verdict**: malicious +35, plus up to +25 scaled from URLScan's
  own confidence score
- **Registration recency**: <30 days +25, <90 +15, <180 +5
- **Mail capability**: up to +20 from the SPF/DKIM/DMARC assessment (MX
  alone +15)
- **Live content**: HTTPS +12 / HTTP +8, redirect +5, valid TLS +5
- **Certificate Transparency** +8, sound-alike +5, registered at all +5

Capped at 100. Excel colour-codes it: red 70+, orange 50–69, yellow 30–49.

## Change detection: what the alerts mean

Alerts fire on **changes between scans**, never the full result set:

| Change | Meaning | Typical action |
|---|---|---|
| `NEW` | A permutation registered since the last scan | Triage; recent + mail-capable is the classic pre-phish setup |
| `ESCALATED` | Risk went up — e.g. a credential form appeared, or the domain gained send capability | This is the highest-value alert the tool produces. Investigate now |
| `ACTIVATED` | Went from parked/inactive to serving content | Look at what it serves |
| `CHANGED` | Registration or infrastructure changed (registrar, IPs, …) | Usually informational |
| `RESOLVED` | No longer registered or no longer resolving | Confirm it matches your takedown, then close your ticket |

The full delta also lands in `results/latest_changes.json` for automation.

## From finding to takedown

A takedown request stands on evidence the registrar can verify themselves.
The report is built to give you those sentences directly, e.g.:

> `examp1e-login.com` was registered 9 days ago, publishes SPF and DKIM
> (send-capable), presents a valid TLS certificate, and serves a form with a
> password field posting to a different domain while naming our brand.

Every clause maps to a column: Age, Mail, TLS, Page. The registrar's abuse
contact is usually in the WHOIS emails column. That is also why scores are
deterministic — *"our model ranked it first"* convinces nobody, and the
model's opinion is deliberately absent from the score.

## Triage tips

- Work top-of-list first, but scan the `Mail` column for SEND-CAPABLE
  regardless of score — mail capability with no website is invisible to
  URLScan and HTTP probing.
- Record your decisions as you go: `--label domain.com=acted` /
  `--label domain.com=dismissed`. After ~30 labels you can train the
  ranking model ([ML_TRIAGE.md](ML_TRIAGE.md)) so future reports sort by
  what *your* team acts on.
- `--ai` adds a written assessment per high-risk finding
  ([AI_ANALYSIS.md](AI_ANALYSIS.md)) — it explains, it never scores.
- A domain you dismissed stays in future reports (it is still registered);
  change detection keeps quiet about it unless something about it changes.

## See also

- [QUICKSTART.md](QUICKSTART.md) — first scan in 10 minutes
- [ALERTING.md](ALERTING.md) — getting the change feed into Slack/Jira/…
- [API_KEYS_SETUP.md](API_KEYS_SETUP.md) — enabling URLScan enrichment
- The committed samples in `results/sample.*` show a real scan of `eff.org`
