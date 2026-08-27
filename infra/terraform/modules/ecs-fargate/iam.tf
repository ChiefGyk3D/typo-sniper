data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# --- Execution role: what ECS itself needs to start the task -----------------

data "aws_iam_policy_document" "execution_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.execution_assume.json
  tags               = var.common.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Task role: what the scanner itself may do -------------------------------

data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
  tags               = var.common.tags
}

data "aws_iam_policy_document" "task" {
  # Reports go up; nothing is ever read back or deleted. A compromised scan
  # task should not be able to read another run's findings, so no s3:GetObject.
  statement {
    sid       = "WriteReports"
    actions   = ["s3:PutObject"]
    resources = ["${var.common.results_bucket_arn}/*"]
  }

  # One specific secret, not "read every secret in the account".
  statement {
    sid       = "ReadOwnSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.common.secret_arn]
  }

  statement {
    sid = "MountStateFileSystem"

    actions = [
      "elasticfilesystem:ClientMount",
      "elasticfilesystem:ClientWrite",
    ]

    resources = ["arn:aws:elasticfilesystem:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:file-system/${var.common.state_file_system_id}"]

    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [var.common.state_access_point_arn]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name_prefix = "${var.name}-task-"
  role        = aws_iam_role.task.id
  policy      = data.aws_iam_policy_document.task.json
}

# --- Scheduler role: what EventBridge may start ------------------------------

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }

    # Without this, any account able to reach the scheduler service could
    # assume this role: the classic confused deputy.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name_prefix        = "${var.name}-sched-"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
  tags               = var.common.tags
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    sid       = "RunScanTask"
    actions   = ["ecs:RunTask"]
    resources = ["${aws_ecs_task_definition.scan.arn_without_revision}:*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [local.cluster_arn]
    }
  }

  statement {
    sid     = "PassTaskRoles"
    actions = ["iam:PassRole"]

    resources = [
      aws_iam_role.execution.arn,
      aws_iam_role.task.arn,
    ]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name_prefix = "${var.name}-sched-"
  role        = aws_iam_role.scheduler.id
  policy      = data.aws_iam_policy_document.scheduler.json
}
