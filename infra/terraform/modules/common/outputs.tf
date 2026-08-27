output "results_bucket" {
  description = "S3 bucket holding scan reports."
  value       = aws_s3_bucket.results.id
}

output "results_bucket_arn" {
  description = "ARN of the results bucket."
  value       = aws_s3_bucket.results.arn
}

output "state_file_system_id" {
  description = "EFS file system holding scan history."
  value       = aws_efs_file_system.state.id
}

output "state_access_point_id" {
  description = "EFS access point the task mounts."
  value       = aws_efs_access_point.state.id
}

output "state_access_point_arn" {
  description = "ARN of the EFS access point, for IAM conditions."
  value       = aws_efs_access_point.state.arn
}

output "task_security_group_id" {
  description = "Security group to attach to the scan task."
  value       = aws_security_group.task.id
}

output "secret_arn" {
  description = "Secrets Manager secret holding API keys and webhook URLs."
  value       = aws_secretsmanager_secret.app.arn
}

output "secret_name" {
  description = "Secret name, for TYPO_SNIPER_AWS_SECRET_NAME."
  value       = aws_secretsmanager_secret.app.name
}

output "tags" {
  description = "Merged tag set, for reuse by the deployment modules."
  value       = local.tags
}
