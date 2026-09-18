variable "project_name" {
  type        = string
  description = "Short name used to build resource names."
  default     = "iam-detection"
}

variable "aws_region" {
  type        = string
  description = "Single region for this project. Multi-region is an explicit non-goal."
  default     = "us-east-1"
}
