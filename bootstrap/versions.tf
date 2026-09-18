terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Local state on purpose — this module creates the bucket that everything
  # else uses as remote state, so it can't depend on that bucket existing yet.
}
