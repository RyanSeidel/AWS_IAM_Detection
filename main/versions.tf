terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Empty on purpose — values come from backend.hcl via -backend-config so
  # the account ID is never committed. See bootstrap/ for how the bucket
  # this points at gets created.
  backend "s3" {}
}
