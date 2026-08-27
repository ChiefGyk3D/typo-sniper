# A scheduled scanner as a CronJob on an existing EKS cluster.
#
# Assumes the cluster already exists and the EFS CSI driver is installed. This
# module deliberately creates neither: a scan job has no business owning a
# cluster, and the CSI driver is a cluster-wide concern.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.30"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = var.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

locals {
  # The IRSA trust policy keys off the issuer URL without its scheme.
  oidc_url = replace(data.aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
}

data "aws_iam_openid_connect_provider" "cluster" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

module "common" {
  source = "../../modules/common"

  name       = var.name
  vpc_id     = data.aws_eks_cluster.this.vpc_config[0].vpc_id
  subnet_ids = var.subnet_ids

  tags = {
    Environment = var.environment
  }
}

module "scanner" {
  source = "../../modules/eks-cronjob"

  name      = var.name
  namespace = var.namespace
  common    = module.common

  oidc_provider_arn = data.aws_iam_openid_connect_provider.cluster.arn
  oidc_provider_url = local.oidc_url

  domains = var.domains

  # Daily at 06:00, cluster time.
  schedule = "0 6 * * *"

  extra_args = ["--notify", "slack"]
}
