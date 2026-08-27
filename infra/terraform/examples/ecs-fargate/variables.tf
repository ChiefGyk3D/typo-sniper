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

variable "vpc_id" {
  description = "Existing VPC for the EFS mount targets and the scan task."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets with outbound internet access."
  type        = list(string)
}

variable "assign_public_ip" {
  description = "Set true for public subnets without a NAT gateway."
  type        = bool
  default     = false
}

variable "domains" {
  description = "Domains to monitor."
  type        = list(string)
  default     = ["example.com"]
}
