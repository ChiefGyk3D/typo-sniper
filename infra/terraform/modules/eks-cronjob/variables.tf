variable "name" {
  description = "Name prefix for Kubernetes and AWS resources."
  type        = string
  default     = "typo-sniper"
}

variable "namespace" {
  description = "Kubernetes namespace to deploy into. Must already exist."
  type        = string
  default     = "security"
}

variable "image" {
  description = <<-EOT
    Container image to run. Pin a version tag rather than :latest — a
    scheduled job silently picking up a new image is how a scan starts failing
    at 3am with nothing in the change log to explain it.
  EOT
  type        = string
  default     = "ghcr.io/chiefgyk3d/typo-sniper:2.1.0"
}

variable "schedule" {
  description = "Kubernetes CronJob schedule, in cluster time. Daily at 06:00."
  type        = string
  default     = "0 6 * * *"
}

variable "domains" {
  description = "Domains to monitor. Mounted as a ConfigMap."
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

variable "oidc_provider_arn" {
  description = <<-EOT
    ARN of the cluster's IAM OIDC provider, for IRSA. From the aws_eks_cluster
    data source or the terraform-aws-eks module's oidc_provider_arn output.

    The cluster itself is deliberately not created here: most teams running
    EKS already have one, and a scan job has no business owning a cluster.
  EOT
  type        = string
}

variable "oidc_provider_url" {
  description = "Cluster OIDC issuer URL, without the https:// scheme."
  type        = string
}

variable "efs_csi_storage_class" {
  description = <<-EOT
    StorageClass backed by the EFS CSI driver. The driver must already be
    installed in the cluster; this module does not install it.
  EOT
  type        = string
  default     = "efs-sc"
}

variable "cpu_request" {
  description = "CPU request for the scan pod."
  type        = string
  default     = "500m"
}

variable "memory_request" {
  description = "Memory request for the scan pod."
  type        = string
  default     = "1Gi"
}

variable "memory_limit" {
  description = "Memory limit for the scan pod."
  type        = string
  default     = "2Gi"
}

variable "active_deadline_seconds" {
  description = <<-EOT
    Seconds before a stuck scan is killed. A scan of a large brand takes
    minutes, not hours; the default gives generous headroom while still
    guaranteeing a hung run cannot block the next schedule forever.
  EOT
  type        = number
  default     = 14400
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
