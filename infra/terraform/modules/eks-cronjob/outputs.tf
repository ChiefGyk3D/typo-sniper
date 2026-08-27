output "cron_job_name" {
  description = "Kubernetes CronJob running the scan."
  value       = kubernetes_cron_job_v1.scan.metadata[0].name
}

output "service_account_name" {
  description = "Service account the pod runs as."
  value       = kubernetes_service_account_v1.scanner.metadata[0].name
}

output "irsa_role_arn" {
  description = "IAM role the pod assumes via IRSA."
  value       = aws_iam_role.irsa.arn
}

output "state_claim_name" {
  description = "PVC holding scan history between runs."
  value       = kubernetes_persistent_volume_claim_v1.state.metadata[0].name
}
