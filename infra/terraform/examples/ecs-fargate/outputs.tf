output "results_bucket" {
  description = "Where scan reports land."
  value       = module.common.results_bucket
}

output "secret_name" {
  description = "Populate this secret with your API keys and webhook URLs."
  value       = module.common.secret_name
}

output "log_group" {
  description = "CloudWatch log group holding scan output."
  value       = module.scanner.log_group
}

output "run_now" {
  description = "Command to trigger a scan immediately, without waiting for the schedule."
  value = join(" ", [
    "aws ecs run-task",
    "--cluster ${module.scanner.cluster_arn}",
    "--task-definition ${module.scanner.task_definition_arn}",
    "--launch-type FARGATE",
    "--network-configuration 'awsvpcConfiguration={subnets=[${join(",", var.subnet_ids)}],securityGroups=[${module.common.task_security_group_id}],assignPublicIp=${var.assign_public_ip ? "ENABLED" : "DISABLED"}}'",
  ])
}
