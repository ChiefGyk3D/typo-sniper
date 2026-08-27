variable "name" {
  description = "Name prefix for every resource this module creates."
  type        = string
  default     = "typo-sniper"
}

variable "image" {
  description = <<-EOT
    Container image to run. Pin a version tag rather than :latest — a scheduled
    job silently picking up a new image is how a scan starts failing at 3am
    with nothing in the change log to explain it.
  EOT
  type        = string
  default     = "ghcr.io/chiefgyk3d/typo-sniper:2.1.0"
}

variable "schedule_expression" {
  description = "EventBridge schedule. Default is daily at 06:00 UTC."
  type        = string
  default     = "cron(0 6 * * ? *)"
}

variable "domains" {
  description = <<-EOT
    Domains to monitor. Written into the task definition as a file the
    entrypoint reads, so changing this list is a Terraform apply rather than a
    rebuild of the image.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.domains) > 0
    error_message = "at least one domain to monitor is required."
  }
}

variable "extra_args" {
  description = "Additional CLI arguments, e.g. [\"--notify\", \"slack\"]."
  type        = list(string)
  default     = []
}

variable "cluster_arn" {
  description = "Existing ECS cluster to run in. Null creates a dedicated one."
  type        = string
  default     = null
}

variable "cpu" {
  description = "Fargate task CPU units. 1024 = 1 vCPU."
  type        = number
  default     = 1024
}

variable "memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 2048
}

variable "task_timeout_hours" {
  description = <<-EOT
    Hours before a stuck scan is considered failed. Fargate has no task
    timeout of its own, so this drives the EventBridge retry policy. Note this
    is one reason Lambda is not offered: a scan of a large brand routinely
    exceeds Lambda's 15-minute ceiling.
  EOT
  type        = number
  default     = 4
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 30
}

variable "assign_public_ip" {
  description = <<-EOT
    Give the task a public IP. Required when running in public subnets without
    a NAT gateway; the scanner cannot work without outbound access.
  EOT
  type        = bool
  default     = false
}

variable "subnet_ids" {
  description = "Subnets to run the task in."
  type        = list(string)
}

variable "common" {
  description = "The entire output object of the `common` module."
  type = object({
    results_bucket         = string
    results_bucket_arn     = string
    state_file_system_id   = string
    state_access_point_id  = string
    state_access_point_arn = string
    task_security_group_id = string
    secret_arn             = string
    secret_name            = string
    tags                   = map(string)
  })
}
