# Alerting, Notifications, and Ticketing

Typo Sniper alerts on **changes**, never on the full result set. A daily scan
that re-reported the same seventy registered lookalikes every morning would be
ignored within a week; one that says "a new lookalike appeared three days ago
and it has MX records" gets read.

## Channels

| Channel | What it does | Needs |
|---|---|---|
| `slack` | Block Kit message to an incoming webhook | webhook URL |
| `discord` | Embed to a webhook, coloured by severity | webhook URL |
| `teams` | Adaptive Card via Power Automate | workflow URL |
| `matrix` | Room message via the client-server API | homeserver, token, room |
| `jira` | **One ticket per domain**, deduplicated | site, email, token, project |
| `webhook` | Raw JSON to any endpoint | URL, optional auth header |
| `email` | SMTP, HTML and plain text | SMTP settings |

```bash
python src/typo_sniper.py -i domains.txt --notify slack jira
```

Every credential resolves through the secrets backends, so none of them need
to live in `config.yaml`. See [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md).

## Gating

Three settings decide whether anything is sent at all:

```yaml
notify_min_changes: 1        # Suppress alerts below this many changes
notify_on_no_changes: false  # Send a "nothing changed" message anyway
notify_timeout: 20
```

## Alerting versus ticketing

Slack, Discord, Teams, Matrix, email, and webhook are **alerting**: a message
is disposable, and sending the same one twice is noise.

Jira is **ticketing**, and a ticket is state. That difference drives its
design.

### Microsoft Teams

Use a Power Automate **"When a Teams webhook request is received"** trigger and
paste its URL into `teams_webhook_url`. Typo Sniper sends an Adaptive Card in
the message envelope that trigger expects.

The older Office 365 connector — the one with an `outlook.office.com` URL that
took a `MessageCard` — has been **retired by Microsoft**. If you have an old
connector URL lying around, it will not work; create a workflow instead.

### Matrix

```yaml
matrix_homeserver: https://matrix.example.org
matrix_room_id: '!yourroomid:example.org'
```

```bash
export TYPO_SNIPER_MATRIX_ACCESS_TOKEN="syt_..."
```

No SDK is required — this talks to the client-server API directly. Two details
worth knowing:

- **The access token is sent as a bearer header**, not as the deprecated
  `?access_token=` query parameter, which would put the credential in the
  homeserver's request logs and in every proxy along the way.
- **Each send carries a fresh transaction ID**, so a retried delivery is
  idempotent at the homeserver rather than double-posting.

Messages are sent as both plain text and HTML. The HTML half is escaped on top
of the markup-stripping every channel already does, because that half is
rendered as markup.

### Jira

```yaml
jira_url: https://you.atlassian.net
jira_email: security@you.example
jira_project_key: SEC
jira_issue_type: Task
jira_max_issues_per_run: 10
jira_labels: [typosquatting]
```

```bash
export TYPO_SNIPER_JIRA_API_TOKEN="..."
```

Three rules make this safe to run on a schedule:

**One issue per domain, not per scan.** A lookalike is tracked from detection
through takedown, which is the unit of work an analyst actually has.

**Deduplicated by a deterministic label.** Before creating anything, the
project is searched for an open issue carrying `typosniper-<hash of domain>`.
A scheduled scan therefore does not file the same lookalike every morning.
An issue that was *closed* stays closed — if that domain later comes back, a
new ticket is raised, which is correct, because it genuinely is a new event.

**Creation is capped per run** (`jira_max_issues_per_run`, default 10). The
first scan of a well-known brand can surface hundreds of registered lookalikes,
and turning that into hundreds of tickets would be the most destructive thing
this tool could do to someone's backlog. When the cap bites, the run logs how
many were not filed, and those findings remain in the scan report and in
`latest_changes.json`. The cap keeps the highest-risk findings.

Only `new`, `escalated`, and `activated` changes are ticketed. A `resolved`
domain is good news, not work, and a `changed` one is usually a detail on
something already tracked.

Credentials go out as a Basic `Authorization` header built with the standard
library — never in the URL, where they would land in access logs.

## Untrusted content

Every payload carries third-party data: domain names, registrant fields, page
titles, all written by the people being investigated.

The chat channels **plain-text** their content, stripping control characters
and the markup characters (`` ` ``, `*`, `_`, `~`, `|`, `<`, `>`, `[`, `]`)
that would otherwise let a registrant forge formatting or embed a link in your
Slack channel.

The `webhook` channel deliberately does **not**. Its consumer is a machine — a
SIEM, a script, a ticketing system — and a domain name is the primary key it
correlates on, so mangling `g00gle<script>.com` into something prettier would
corrupt the very field that matters. JSON encoding already prevents the payload
from breaking out of its structure. Treat the values as untrusted at the point
you render them.

## Failure behaviour

A channel that fails is logged and the others still fire. Delivery results are
returned per channel, so a failing Slack webhook never costs you the Jira
ticket. No alerting failure affects the scan, the report, or the exports.
