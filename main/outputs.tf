output "cloudtrail_bucket" {
  description = "Name of the CloudTrail log bucket."
  value       = aws_s3_bucket.cloudtrail.id
}

output "trail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.main.arn
}

output "verify_delivery_command" {
  description = "Run ~15 minutes after a console change (e.g. create/delete an IAM user) to confirm log delivery. Presence of .json.gz objects means the pipeline works."
  value       = "aws s3 ls s3://${aws_s3_bucket.cloudtrail.id}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/${var.aws_region}/ --recursive"
}
