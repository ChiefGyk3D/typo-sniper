# Infrastructure as Code

Terraform / OpenTofu modules for running Typo Sniper as a scheduled scanner on
AWS. Two deployment shapes, sharing one set of supporting resources.

```
infra/terraform/
├── modules/
│   ├── common/        S3 reports bucket, EFS state, Secrets Manager, security groups
│   ├── ecs-fargate/   Scheduled Fargate task via EventBridge Scheduler
│   └── eks-cronjob/   Kubernetes CronJob on an existing EKS cluster
└── examples/
    ├── ecs-fargate/   Complete working deployment
    └── eks-cronjob/   Complete working deployment
```

## Which one

**ECS Fargate** unless you have a reason not to. Typo Sniper is a batch job: it
wakes up, scans for a few minutes, writes a report, and exits. Fargate bills
for those minutes and there is no cluster idling between runs.

**EKS CronJob** if your scheduling, alerting, and on-call already run through
Kubernetes. Same workload, same bucket, same secret — the difference is only
what starts the container.

**Not Lambda.** A scan of a well-known brand routinely runs longer than
Lambda's 15-minute ceiling, and the failure mode is a truncated scan that looks
like a clean one.

## The thing that is easy to get wrong

Typo Sniper detects **changes**. It compares each scan against the previous one
and keeps that history in `state_dir`.

A container starts with an empty filesystem. Put `state_dir` on ephemeral
storage and every scheduled run looks like a first run: no deltas are computed,
no alerts fire, and the scanner appears to work perfectly while doing none of
the job it was deployed for. Nothing errors. Nothing warns.

Both modules mount **EFS** at `state_dir` for exactly this reason, and the
`common` module enables EFS backups — losing scan history means losing the
baseline every alert is measured against, so the next run reports every known
lookalike as new.

If you deploy this some other way, that is the detail to get right.

## Quick start

```bash
cd infra/terraform/examples/ecs-fargate

cat > terraform.tfvars <<'VARS'
vpc_id     = "vpc-0123456789abcdef0"
subnet_ids = ["subnet-0a1b2c3d", "subnet-4e5f6a7b"]
domains    = ["yourbrand.com", "yourbrand.co.uk"]
VARS

tofu init
tofu apply
```

Then populate the secret it created. It is deliberately **not** managed by
Terraform: putting credentials in a variable writes them to state in clear
text, which is the thing a secrets backend exists to prevent.

```bash
aws secretsmanager put-secret-value \
  --secret-id "$(tofu output -raw secret_name)" \
  --secret-string '{
    "urlscan_api_key": "...",
    "slack_webhook_url": "https://hooks.slack.com/services/...",
    "ai_api_key": "sk-ant-..."
  }'
```

Key names are Typo Sniper's own — see
[SECRETS_MANAGEMENT.md](../docs/guides/SECRETS_MANAGEMENT.md). The task reads
them through the scanner's AWS backend, so nothing lands in the task
definition, where it would be readable by anyone with
`ecs:DescribeTaskDefinition`.

Trigger a run without waiting for the schedule:

```bash
eval "$(tofu output -raw run_now)"
```

## What it creates

| Resource | Why |
|---|---|
| S3 bucket | Scan reports. Versioned, encrypted, public access blocked, lifecycle-expired |
| EFS file system + access point | Scan history between runs. Encrypted, backed up |
| Secrets Manager secret | API keys and webhook URLs, populated out of band |
| Security groups | Task egress only; NFS restricted to the task's own group |
| IAM roles | Execution, task, and either scheduler or IRSA |
| CloudWatch log group | Scan output, retained 30 days by default |
| EventBridge schedule *or* CronJob | Whatever starts the scan |

### Permissions

The scan task can do three things and nothing else:

- **`s3:PutObject`** to its own bucket. No `GetObject` and no `DeleteObject` —
  a compromised scan task should not be able to read another run's findings.
- **`secretsmanager:GetSecretValue`** on one named secret, not every secret in
  the account.
- **Mount one EFS access point**, conditioned on the access point ARN.

The EventBridge scheduler role can start this one task definition on this one
cluster, and pass only the two roles the task needs. Its trust policy is scoped
with `aws:SourceAccount` to close the confused-deputy path. The EKS variant's
IRSA trust policy is scoped to one service account in one namespace; without
that condition any pod in the cluster could assume the role.

## Requirements

Both:
- OpenTofu ≥ 1.5 or Terraform ≥ 1.5
- AWS provider ≥ 6.0
- An existing VPC with subnets that have outbound internet access. The
  scanner's entire job is reaching DNS, RDAP, and suspicious hosts.

EKS additionally:
- An existing cluster with an IAM OIDC provider
- The **EFS CSI driver installed** — this module does not install it, because
  a CSI driver is a cluster-wide concern and a scan job has no business owning
  one
- The target namespace already created

## Pin the image

Both modules default to a version tag, not `:latest`. Keep it that way. A
scheduled job silently picking up a new image is how a scan starts failing at
3am with nothing in the change log to explain it.

## Cost

The scan itself is minutes of Fargate a day. In practice the standing cost is
EFS (a few GB at most, with IA transition after 30 days) and S3. Container
Insights is enabled on a cluster this module creates; turn it off if you do not
want the CloudWatch charge.

## Verification status

These modules are **syntax-checked and canonically formatted**
(`tofu fmt -check -recursive`, which parses the HCL and rejects malformed
configuration) but have **not been schema-validated or planned** against real
AWS. Run `tofu validate` and `tofu plan` in your own account before applying —
that will catch any argument that a provider version rejects.
