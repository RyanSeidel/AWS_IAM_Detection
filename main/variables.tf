variable "project_name" {
  type        = string
  description = "Short name used to build resource names. Must match bootstrap/'s value."
  default     = "iam-detection"
}

variable "aws_region" {
  type        = string
  description = "Single region for this project. Multi-region is an explicit non-goal."
  default     = "us-east-1"
}

variable "cloudtrail_log_retention_days" {
  type        = number
  description = "CloudWatch Logs retention for the CloudTrail delivery group. The AWS default is never-expire, which this project never wants."
  default     = 90
}
