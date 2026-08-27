variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name prefix for created resources."
  type        = string
  default     = "typo-sniper"
}

variable "environment" {
  description = "Environment tag."
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "Existing EKS cluster to deploy into."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace. Must already exist."
  type        = string
  default     = "security"
}

variable "subnet_ids" {
  description = <<-EOT
    Subnets for the EFS mount targets. Use the cluster's node subnets so the
    pods can reach the file system.
  EOT
  type        = list(string)
}

variable "domains" {
  description = "Domains to monitor."
  type        = list(string)
  default     = ["example.com"]
}
