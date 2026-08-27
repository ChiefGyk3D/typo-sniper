output "results_bucket" {
  description = "Where scan reports land."
  value       = module.common.results_bucket
}

output "secret_name" {
  description = "Populate this secret with your API keys and webhook URLs."
  value       = module.common.secret_name
}

output "cron_job" {
  description = "The CronJob running the scan."
  value       = module.scanner.cron_job_name
}

output "run_now" {
  description = "Command to trigger a scan immediately."
  value       = "kubectl -n ${var.namespace} create job --from=cronjob/${module.scanner.cron_job_name} ${var.name}-manual"
}
