# Secrets Management

Typo Sniper handles material that should never sit in a config file: threat
intelligence API keys, Slack and Discord webhook URLs, SMTP passwords, and LLM
provider keys. Every one of them is resolved through a chain of secrets
backends, so the repository and `config.yaml` stay clean.

## Backends

| Backend | Needs installing | Configured by |
|---|---|---|
| `env` | nothing | `TYPO_SNIPER_<NAME>` variables |
| `doppler` | nothing | `doppler run`, or `DOPPLER_TOKEN` |
| `aws` | `boto3` | `aws_secret_name` / `AWS_SECRET_NAME` |
| `vault` | nothing | `VAULT_ADDR` + a token |
| `azure` | `azure-keyvault-secrets`, `azure-identity` | `azure_key_vault_url` |
| `gcp` | `google-cloud-secret-manager` | `gcp_project_id` |
| `onepassword` | the `op` CLI | `onepassword_vault` + `onepassword_item` |

Doppler and HashiCorp Vault are reached over HTTPS with the Python standard
library, so the two stores most often self-hosted work with nothing extra
installed.

```bash
pip install -e ".[aws]"          # or .[azure], .[gcp], .[secrets-all]
```

## Resolution order

Backends are consulted in the order given by `secrets_backends`, defaulting to:

```
env → doppler → aws → vault → azure → gcp → onepassword
```

Three rules govern the chain:

1. **A value already in `config.yaml` wins.** An explicit setting is a
   deliberate act and is never silently overridden by an entry in a shared
   vault.
2. **`env` is always first, and is re-inserted if you leave it out.** Overriding
   one key for one run must never require editing a vault the whole team shares.
3. **An unconfigured backend is skipped, and a failing one is passed over.** A
   secrets store being unreachable degrades to the next backend; it never stops
   a scan that can still run without that key.

## Naming

The canonical name of a secret is its config field in `lower_snake_case`, for
example `urlscan_api_key`. Each backend maps it to its own convention:

| Backend | Looked up as |
|---|---|
| `env` | `TYPO_SNIPER_URLSCAN_API_KEY` |
| `doppler` | `URLSCAN_API_KEY` |
| `aws` | key `urlscan_api_key` (or uppercase) inside the JSON secret |
| `vault` | key `urlscan_api_key` at the KV path |
| `azure` | `urlscan-api-key` — Key Vault allows only letters, digits, dashes |
| `gcp` | `urlscan_api_key`, then `urlscan-api-key` |
| `onepassword` | field `urlscan_api_key` on the configured item |

A handful of vendor-standard variables are also accepted directly:
`URLSCAN_API_KEY`, `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`,
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
`OLLAMA_HOST`. The `TYPO_SNIPER_`-prefixed form always wins over these.

## Checking your setup

```bash
python src/typo_sniper.py --secrets-check
```

This prints which backends are reachable and where each credential resolved
from. It never prints a value — debugging a missing key with `echo` puts the
value in your shell history, which is what this exists to avoid.

```
Secrets backends
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Backend     ┃ Status         ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ env         │ ready          │
│ doppler     │ ready          │
│ vault       │ not configured │
└─────────────┴────────────────┘

Credentials
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Name              ┃ Resolved ┃ Source  ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ urlscan_api_key   │ yes      │ doppler │
│ slack_webhook_url │ no       │ —       │
└───────────────────┴──────────┴─────────┘
```

## Per-backend setup

### Environment variables

Always available, always first.

```bash
export TYPO_SNIPER_URLSCAN_API_KEY="..."
export TYPO_SNIPER_ENABLE_URLSCAN=true
python src/typo_sniper.py -i domains.txt
```

A `.env` file in the working directory or any parent is loaded automatically.

### Doppler

Either wrap the command, which needs no configuration at all:

```bash
doppler run -- python src/typo_sniper.py -i domains.txt
```

…or give the process a service token and let it fetch its own config, which
suits a container whose entry point you do not control:

```bash
export DOPPLER_TOKEN="dp.st.prd...."
export DOPPLER_PROJECT="typo-sniper"   # optional if the token is config-scoped
export DOPPLER_CONFIG="prd"
python src/typo_sniper.py -i domains.txt
```

### AWS Secrets Manager

One secret holding a JSON object of many keys, which is how the console's
key/value editor stores them:

```bash
aws secretsmanager create-secret \
  --name typo-sniper/prod \
  --secret-string '{"urlscan_api_key":"...","slack_webhook_url":"https://..."}'

export AWS_SECRET_NAME="typo-sniper/prod"
export AWS_REGION="us-east-1"
```

Credentials come from the standard boto3 chain, so an EC2 instance profile,
an ECS task role, or IRSA on EKS all work with nothing further set.

### HashiCorp Vault

```bash
vault kv put secret/typo-sniper \
  urlscan_api_key="..." \
  slack_webhook_url="https://..."

export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="hvs...."        # or just run `vault login` first
export VAULT_PATH="secret/data/typo-sniper"   # this is the default
```

If `VAULT_TOKEN` is unset, the `~/.vault-token` file written by `vault login`
is read, so a developer already signed in needs no further setup. KV v2 and
KV v1 payloads are both handled. Vault Enterprise namespaces are supported via
`VAULT_NAMESPACE`.

### Azure Key Vault

```bash
pip install -e ".[azure]"
az keyvault secret set --vault-name your-vault --name urlscan-api-key --value "..."
export AZURE_KEY_VAULT_URL="https://your-vault.vault.azure.net/"
```

Authentication uses `DefaultAzureCredential`, so managed identity, a service
principal, or `az login` all work.

### Google Cloud Secret Manager

```bash
pip install -e ".[gcp]"
echo -n "..." | gcloud secrets create urlscan_api_key --data-file=-
export GCP_PROJECT_ID="brand-security"
```

Authentication uses Application Default Credentials. The `latest` version of
each secret is read.

### 1Password

```bash
export OP_VAULT="Security"
export OP_ITEM="typo-sniper"
op signin        # or set OP_SERVICE_ACCOUNT_TOKEN in CI
```

Values are read as `op://Security/typo-sniper/urlscan_api_key`. The `op` binary
is resolved to an absolute path and run without a shell.

## Deployment patterns

### Docker

```bash
docker run -e DOPPLER_TOKEN="dp.st.prd...." typo-sniper -i domains.txt
```

### Kubernetes

Either mount an External Secrets Operator-synced Secret as environment
variables, or let the pod reach Vault directly with a projected service account
token — Typo Sniper needs no Vault client library for the latter.

### CI/CD

Use the platform's own secret store, exported as `TYPO_SNIPER_*` variables.
GitHub Actions secrets, GitLab CI/CD variables, and Doppler service tokens all
land in the `env` backend with no configuration.

## What is never logged

- **No secret value is ever logged**, at any level, by any backend.
- **Backend failures record only the exception type**, never its message. A
  store's error text can echo the request body, the token, or the secret itself.
- **`--secrets-check` prints names and sources only.**

## Rotation

Secrets are read once at startup and cached for the life of the process. In
watch mode (`--watch`), a rotated secret takes effect on the next restart, not
the next cycle. For short rotation windows, run one scan per invocation from a
scheduler rather than a long-lived watch loop.
