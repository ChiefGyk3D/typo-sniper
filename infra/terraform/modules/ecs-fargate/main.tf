# A scheduled Fargate task.
#
# This shape is chosen deliberately. Typo Sniper is a batch job: it wakes up,
# scans for a few minutes, writes a report, and exits. Fargate bills for those
# minutes and nothing else, and there is no cluster sitting idle between runs.

locals {
  cluster_arn  = var.cluster_arn != null ? var.cluster_arn : aws_ecs_cluster.this[0].arn
  domains_file = "/app/data/monitored_domains.txt"
  state_dir    = "/app/state"

  # Written by the entrypoint before the scan starts, so the monitored list is
  # Terraform-managed rather than baked into the image.
  bootstrap = join(" && ", [
    "printf '%s\\n' ${join(" ", [for d in var.domains : format("%q", d)])} > ${local.domains_file}",
    "typo-sniper ${join(" ", concat(["-i", local.domains_file, "--output", "/app/results"], var.extra_args))}",
    # Shipped in the image; see docker/upload-results.py. Reads
    # RESULTS_BUCKET and RESULTS_PREFIX from the environment below.
    "typo-sniper-upload",
  ])
}

resource "aws_ecs_cluster" "this" {
  count = var.cluster_arn == null ? 1 : 0

  name = var.name
  tags = var.common.tags

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "scan" {
  name_prefix       = "/ecs/${var.name}-"
  retention_in_days = var.log_retention_days
  tags              = var.common.tags
}

resource "aws_ecs_task_definition" "scan" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  tags                     = var.common.tags

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "state"

    efs_volume_configuration {
      file_system_id     = var.common.state_file_system_id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = var.common.state_access_point_id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    {
      name      = "scan"
      image     = var.image
      essential = true

      # The image's entrypoint is the typo-sniper console script, so it is
      # overridden here to write the domain list first and ship results after.
      entryPoint = ["/bin/sh", "-c"]
      command    = [local.bootstrap]

      mountPoints = [
        {
          sourceVolume  = "state"
          containerPath = local.state_dir
          readOnly      = false
        }
      ]

      environment = [
        # Resolves credentials through the AWS Secrets Manager backend rather
        # than baking them into the task definition, where they would be
        # readable by anyone with ecs:DescribeTaskDefinition.
        { name = "TYPO_SNIPER_AWS_SECRET_NAME", value = var.common.secret_name },
        { name = "AWS_REGION", value = data.aws_region.current.region },
        { name = "TYPO_SNIPER_STATE_DIR", value = local.state_dir },
        { name = "TYPO_SNIPER_OUTPUT_DIR", value = "/app/results" },
        { name = "RESULTS_BUCKET", value = var.common.results_bucket },
        { name = "RESULTS_PREFIX", value = var.name },
        { name = "PYTHONUNBUFFERED", value = "1" },
      ]

      readonlyRootFilesystem = false # results and the domain list are written

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.scan.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "scan"
        }
      }
    }
  ])
}

resource "aws_scheduler_schedule" "scan" {
  name       = var.name
  group_name = "default"

  flexible_time_window {
    # A scan is not time-critical to the minute, and a window lets AWS spread
    # load rather than starting every scheduled task in the account at once.
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 15
  }

  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = "UTC"

  target {
    arn      = local.cluster_arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.scan.arn_without_revision
      launch_type         = "FARGATE"
      task_count          = 1
      propagate_tags      = "TASK_DEFINITION"

      network_configuration {
        subnets          = var.subnet_ids
        security_groups  = [var.common.task_security_group_id]
        assign_public_ip = var.assign_public_ip
      }
    }

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = var.task_timeout_hours * 3600
    }
  }
}
