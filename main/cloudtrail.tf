locals {
  trail_name      = "${var.project_name}-trail"
  log_bucket_name = "${var.project_name}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  # Built by hand instead of referencing aws_cloudtrail.main.arn: CloudTrail
  # validates the bucket policy at trail-creation time, so referencing the
  # trail resource here would create a dependency cycle. Do not "fix" this.
  trail_arn = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
}

# Log bucket. force_destroy = true here (and only here) so `terraform destroy`
# works cleanly between work sessions on a student account. Not appropriate
# for a production trail.
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.log_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3 — no KMS key, which would be $1/month
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json
}

# Retention is mandatory on every log group in this project — the AWS default
# is never-expire, which is an unbounded, silent cost.
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.trail_name}"
  retention_in_days = var.cloudtrail_log_retention_days
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-cloudtrail-cwl-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Scoped to this one log group's streams — not "*" — because CloudTrail's
# delivery role needs nothing else.
resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-cloudtrail-cwl-policy"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  is_multi_region_trail         = false # single region, us-east-1 — multi-region is an explicit non-goal
  include_global_service_events = true
  is_organization_trail         = false
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn

  # Management events only, both read and write. Data events bill at
  # $0.10/100k with no free copy — the single most common cause of a
  # surprise CloudTrail bill. Insights is likewise never enabled.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
