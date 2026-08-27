terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      # >= 6.0: the aws_region data source exposes `region` from v6 onward,
      # where v5 spelled it `name`. Pinning the major keeps the attribute
      # unambiguous rather than depending on what resolves at init time.
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}
