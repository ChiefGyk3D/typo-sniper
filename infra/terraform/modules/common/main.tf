# Pieces both deployment shapes need: somewhere to put reports, somewhere to
# keep scan state across runs, and somewhere to keep credentials.

locals {
  tags = merge({
    Application = "typo-sniper"
    ManagedBy   = "terraform"
  }, var.tags)
}

# --- Reports -----------------------------------------------------------------

resource "aws_s3_bucket" "results" {
  bucket_prefix = "${var.name}-results-"
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket = aws_s3_bucket.results.id

  # Scan reports name the domains an organisation is defending, which reveals
  # both what they own and what they are worried about. This bucket is never
  # public.
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_versioning" "results" {
  bucket = aws_s3_bucket.results.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  count  = var.results_retention_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.results.id

  rule {
    id     = "expire-reports"
    status = "Enabled"

    filter {}

    expiration {
      days = var.results_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.results]
}

# --- Scan state --------------------------------------------------------------
#
# This is the part that is easy to get wrong, and getting it wrong is silent.
#
# Typo Sniper detects *changes* by comparing each scan against the previous
# one, and it keeps that history in a local directory. A scheduled container
# on ephemeral storage therefore starts from nothing every run: every scan
# looks like a first run, no deltas are ever computed, and no alert ever
# fires. The scanner appears to work perfectly while doing none of the job it
# was deployed for.
#
# EFS gives the task a directory that survives between runs. It is mounted by
# both the ECS and EKS variants for exactly this reason.

resource "aws_efs_file_system" "state" {
  creation_token = "${var.name}-state"
  encrypted      = true
  kms_key_id     = var.kms_key_arn

  # Scan history is small — tens of KB per monitored domain — and read once
  # per run, so bursting throughput is both sufficient and cheapest.
  throughput_mode = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = merge(local.tags, { Name = "${var.name}-state" })
}

resource "aws_efs_backup_policy" "state" {
  file_system_id = aws_efs_file_system.state.id

  backup_policy {
    # Losing scan history means losing the baseline every alert is measured
    # against: the next run reports every known lookalike as new.
    status = "ENABLED"
  }
}

resource "aws_security_group" "efs" {
  name_prefix = "${var.name}-efs-"
  description = "NFS access to the Typo Sniper state file system"
  vpc_id      = var.vpc_id

  tags = merge(local.tags, { Name = "${var.name}-efs" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "task" {
  name_prefix = "${var.name}-task-"
  description = "Typo Sniper scan task"
  vpc_id      = var.vpc_id

  # The scanner's whole job is reaching DNS, RDAP, WHOIS and suspicious hosts,
  # so egress is open. Nothing needs to reach *in*: there is no listener.
  egress {
    description = "Outbound scanning and API traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${var.name}-task" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "efs_from_task" {
  description              = "NFS from the scan task only"
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  security_group_id        = aws_security_group.efs.id
  source_security_group_id = aws_security_group.task.id
}

resource "aws_efs_mount_target" "state" {
  for_each = toset(var.subnet_ids)

  file_system_id  = aws_efs_file_system.state.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "state" {
  file_system_id = aws_efs_file_system.state.id

  # The container runs as uid 10001 (see docker/Dockerfile). The access point
  # owns the directory as that user so the task never needs root to write.
  posix_user {
    uid = 10001
    gid = 10001
  }

  root_directory {
    path = "/typo-sniper"

    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "0755"
    }
  }

  tags = merge(local.tags, { Name = "${var.name}-state" })
}

# --- Credentials -------------------------------------------------------------

resource "aws_secretsmanager_secret" "app" {
  name_prefix = "${var.name}/"
  description = "Typo Sniper API keys, webhook URLs and SMTP credentials"
  kms_key_id  = var.kms_key_arn

  tags = local.tags
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id

  # A placeholder so the secret exists and the task can start. Populate the
  # real values out of band — putting them in Terraform would write them to
  # state in clear text, which is the thing the secrets backend exists to
  # avoid. Keys match Typo Sniper's own names; see
  # docs/guides/SECRETS_MANAGEMENT.md.
  secret_string = jsonencode({
    urlscan_api_key = ""
  })

  lifecycle {
    # Never overwrite values an operator has set by hand or by rotation.
    ignore_changes = [secret_string]
  }
}
