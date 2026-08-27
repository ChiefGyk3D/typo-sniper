# A complete scheduled scanner on ECS Fargate.
#
#   tofu init && tofu apply
#
# Then put the real credentials into the secret this creates — see the module
# README. Nothing is published or scanned until you do.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "common" {
  source = "../../modules/common"

  name       = var.name
  vpc_id     = var.vpc_id
  subnet_ids = var.subnet_ids

  tags = {
    Environment = var.environment
  }
}

module "scanner" {
  source = "../../modules/ecs-fargate"

  name       = var.name
  subnet_ids = var.subnet_ids
  common     = module.common

  domains = var.domains

  # Daily at 06:00 UTC. A scan of a large brand takes minutes.
  schedule_expression = "cron(0 6 * * ? *)"

  # Alerts fire on changes only, so a daily scan that finds nothing new is
  # silent. See docs/guides/ALERTING.md.
  extra_args = ["--notify", "slack"]

  # Only needed when running in public subnets with no NAT gateway. The
  # scanner cannot do its job without outbound access.
  assign_public_ip = var.assign_public_ip
}
