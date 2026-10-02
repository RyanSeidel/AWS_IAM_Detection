data "archive_file" "detector" {
  type        = "zip"
  source_file = "${path.module}/../lambda/handler.py"
  output_path = "${path.module}/detector.zip"
}

resource "aws_iam_role" "detector" {
  name = "insider-threat-detector"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/insider-threat-detector"
  retention_in_days = 7
}

resource "aws_iam_role_policy" "detector" {
  role = aws_iam_role.detector.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.detector.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:Query"]
        Resource = aws_dynamodb_table.baseline.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}
resource "aws_lambda_function" "detector" {
  function_name    = "insider-threat-detector"
  role             = aws_iam_role.detector.arn
  handler          = "handler.handler"
  runtime          = "python3.13"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      BASELINE_TABLE = aws_dynamodb_table.baseline.name
      ALERT_TOPIC = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.detector]
}

locals {
  # Shared by the us-east-1 rule and every regional forwarding rule, so all
  # regions filter identically before reaching the one detector Lambda.
  # Matches mutating calls, plus a short list of sensitive reads (secret theft,
  # and S3 object reads where data events are enabled, e.g. a decoy bucket).
  risky_event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = [{ "anything-but" = ["logs.amazonaws.com"] }]
      userIdentity = {
        invokedBy = [{ exists = false }]
        type      = ["IAMUser", "AssumedRole", "Root"]
      }
      "$or" = [
        { readOnly = [false] },
        { eventName = ["GetParameter", "GetParameters", "GetSecretValue", "GetObject"] }
      ]
    }
  })
}

resource "aws_cloudwatch_event_rule" "risky" {
  name          = "insider-threat-risky-calls"
  event_pattern = local.risky_event_pattern
}

resource "aws_cloudwatch_event_target" "detector" {
  rule = aws_cloudwatch_event_rule.risky.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.risky.arn
}