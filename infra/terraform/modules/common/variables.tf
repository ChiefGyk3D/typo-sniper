variable "name" {
  description = "Name prefix for every resource this module creates."
  type        = string
  default     = "typo-sniper"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}$", var.name))
    error_message = "name must be lowercase alphanumeric with hyphens, 2-31 characters."
  }
}

variable "vpc_id" {
  description = <<-EOT
    VPC to place the EFS mount targets in. Not created here: a module that
    invents a VPC is almost always wrong for an existing account, and the
    scanner only needs outbound access.
  EOT
  type        = string
}

variable "subnet_ids" {
  description = <<-EOT
    Subnets for EFS mount targets and for the scan task. These need a route to
    the internet (NAT gateway, or public subnets with a public IP assigned) —
    the scanner's entire job is reaching DNS, RDAP, and suspicious hosts.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "at least one subnet is required."
  }
}

variable "results_retention_days" {
  description = "Days to keep scan reports in S3 before expiry. 0 disables expiry."
  type        = number
  default     = 90
}

variable "kms_key_arn" {
  description = <<-EOT
    Customer-managed KMS key for the S3 bucket, the EFS file system, and the
    secret. Null uses AWS-managed keys, which is fine for most deployments.
  EOT
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
