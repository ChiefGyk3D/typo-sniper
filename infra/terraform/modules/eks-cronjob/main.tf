# A Kubernetes CronJob on an existing EKS cluster.
#
# The same workload as the ECS variant, for teams whose scheduling, alerting
# and on-call already run through Kubernetes. It shares the `common` module,
# so both shapes write to the same bucket and read the same secret; the
# difference is only what starts the container.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  labels = {
    "app.kubernetes.io/name"       = "typo-sniper"
    "app.kubernetes.io/component"  = "scanner"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  domains_path = "/app/data/monitored_domains.txt"
  state_dir    = "/app/state"
}

# --- IRSA: the pod's AWS identity --------------------------------------------

data "aws_iam_policy_document" "irsa_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    # Scoped to this one service account. Without the `sub` condition any pod
    # in the cluster could assume the role.
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${var.name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "irsa" {
  name_prefix        = "${var.name}-irsa-"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume.json
  tags               = var.common.tags
}

data "aws_iam_policy_document" "irsa" {
  # Reports go up; nothing is read back or deleted.
  statement {
    sid       = "WriteReports"
    actions   = ["s3:PutObject"]
    resources = ["${var.common.results_bucket_arn}/*"]
  }

  statement {
    sid       = "ReadOwnSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.common.secret_arn]
  }
}

resource "aws_iam_role_policy" "irsa" {
  name_prefix = "${var.name}-irsa-"
  role        = aws_iam_role.irsa.id
  policy      = data.aws_iam_policy_document.irsa.json
}

resource "kubernetes_service_account_v1" "scanner" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.labels

    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.irsa.arn
    }
  }
}

# --- Scan state ---------------------------------------------------------------
#
# Same reasoning as the ECS variant: Typo Sniper detects changes by comparing
# each scan against the last, and keeps that history on disk. A CronJob pod
# starts with an empty filesystem, so without a persistent volume every run
# looks like a first run and no delta is ever reported. The scanner would
# appear to work while doing none of the job it was deployed for.

resource "kubernetes_persistent_volume_v1" "state" {
  metadata {
    name   = "${var.name}-state"
    labels = local.labels
  }

  spec {
    capacity = {
      # EFS is elastic; the CSI driver requires a value but does not enforce it.
      storage = "8Gi"
    }

    access_modes                     = ["ReadWriteMany"]
    persistent_volume_reclaim_policy = "Retain"
    storage_class_name               = var.efs_csi_storage_class

    persistent_volume_source {
      csi {
        driver = "efs.csi.aws.com"
        # The access point pins the uid/gid and root directory, so the pod
        # writes as 10001 without needing root.
        volume_handle = "${var.common.state_file_system_id}::${var.common.state_access_point_id}"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim_v1" "state" {
  metadata {
    name      = "${var.name}-state"
    namespace = var.namespace
    labels    = local.labels
  }

  spec {
    access_modes       = ["ReadWriteMany"]
    storage_class_name = var.efs_csi_storage_class
    volume_name        = kubernetes_persistent_volume_v1.state.metadata[0].name

    resources {
      requests = {
        storage = "8Gi"
      }
    }
  }
}

# --- Monitored domains --------------------------------------------------------

resource "kubernetes_config_map_v1" "domains" {
  metadata {
    name      = "${var.name}-domains"
    namespace = var.namespace
    labels    = local.labels
  }

  data = {
    # Terraform-managed rather than baked into the image, so changing the list
    # is an apply rather than a rebuild.
    "monitored_domains.txt" = join("\n", var.domains)
  }
}

# --- The job ------------------------------------------------------------------

resource "kubernetes_cron_job_v1" "scan" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.labels
  }

  spec {
    schedule                      = var.schedule
    concurrency_policy            = "Forbid" # Two scans writing the same state would race
    successful_jobs_history_limit = 3
    failed_jobs_history_limit     = 3
    starting_deadline_seconds     = 3600

    job_template {
      metadata {
        labels = local.labels
      }

      spec {
        backoff_limit           = 2
        active_deadline_seconds = var.active_deadline_seconds

        template {
          metadata {
            labels = local.labels
          }

          spec {
            service_account_name = kubernetes_service_account_v1.scanner.metadata[0].name
            restart_policy       = "OnFailure"

            security_context {
              # Matches the uid the image and the EFS access point use.
              run_as_non_root = true
              run_as_user     = 10001
              run_as_group    = 10001
              fs_group        = 10001
            }

            container {
              name  = "scan"
              image = var.image

              command = ["/bin/sh", "-c"]
              args = [
                join(" && ", [
                  "typo-sniper ${join(" ", concat(["-i", local.domains_path, "--output", "/app/results"], var.extra_args))}",
                  # Shipped in the image; see docker/upload-results.py.
                  "typo-sniper-upload",
                ])
              ]

              env {
                # Credentials come from Secrets Manager through the scanner's
                # own backend chain, using the IRSA identity above.
                name  = "TYPO_SNIPER_AWS_SECRET_NAME"
                value = var.common.secret_name
              }

              env {
                name  = "AWS_REGION"
                value = data.aws_region.current.region
              }

              env {
                name  = "TYPO_SNIPER_STATE_DIR"
                value = local.state_dir
              }

              env {
                name  = "TYPO_SNIPER_OUTPUT_DIR"
                value = "/app/results"
              }

              env {
                name  = "RESULTS_BUCKET"
                value = var.common.results_bucket
              }

              env {
                name  = "RESULTS_PREFIX"
                value = var.name
              }

              env {
                name  = "PYTHONUNBUFFERED"
                value = "1"
              }

              resources {
                requests = {
                  cpu    = var.cpu_request
                  memory = var.memory_request
                }

                limits = {
                  # No CPU limit on purpose: throttling a scan makes it slower,
                  # not safer, and the job is bounded by its deadline anyway.
                  memory = var.memory_limit
                }
              }

              security_context {
                allow_privilege_escalation = false
                read_only_root_filesystem  = false # results are written

                capabilities {
                  drop = ["ALL"]
                }
              }

              volume_mount {
                name       = "state"
                mount_path = local.state_dir
              }

              volume_mount {
                name       = "domains"
                mount_path = "/app/data"
                read_only  = true
              }

              volume_mount {
                name       = "results"
                mount_path = "/app/results"
              }
            }

            volume {
              name = "state"

              persistent_volume_claim {
                claim_name = kubernetes_persistent_volume_claim_v1.state.metadata[0].name
              }
            }

            volume {
              name = "domains"

              config_map {
                name = kubernetes_config_map_v1.domains.metadata[0].name
              }
            }

            volume {
              name = "results"

              empty_dir {
                # Reports are shipped to S3 at the end of the run, so this only
                # has to survive the pod.
                size_limit = "1Gi"
              }
            }
          }
        }
      }
    }
  }
}
