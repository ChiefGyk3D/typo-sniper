output "cluster_arn" {
  description = "ECS cluster the scan runs in."
  value       = local.cluster_arn
}

output "task_definition_arn" {
  description = "Task definition, for running a scan by hand."
  value       = aws_ecs_task_definition.scan.arn
}

output "task_role_arn" {
  description = "Role the scanner itself assumes."
  value       = aws_iam_role.task.arn
}

output "log_group" {
  description = "CloudWatch log group holding scan output."
  value       = aws_cloudwatch_log_group.scan.name
}

output "schedule_name" {
  description = "EventBridge schedule driving the scan."
  value       = aws_scheduler_schedule.scan.name
}
