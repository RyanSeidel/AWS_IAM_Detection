resource "aws_cloudwatch_event_rule" "watchdog_direct" {
  name        = "insider-threat-watchdog"
  description = "Dead-man switch: Alerts SNS directly if the detector is disabled/deleted"

  event_pattern = jsonencode({
    "source": ["aws.events", "aws.lambda", "aws.sns"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": [
        "DisableRule", "RemoveTargets", "DeleteRule",
        "DeleteFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration",
        "PutFunctionConcurrency", "DeleteFunctionConcurrency", "Unsubscribe"
      ],
      "requestParameters": {
        "$or": [
          { "name": [{ "prefix": "insider-threat" }] },
          { "functionName": [{ "prefix": "insider-threat" }] },
          { "SubscriptionArn": [{ "wildcard": "*insider-threat*" }] }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "watchdog_sns" {
  rule      = aws_cloudwatch_event_rule.watchdog_direct.name
  target_id = "WatchdogToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# Grants EventBridge permission to publish directly to the SNS topic
resource "aws_sns_topic_policy" "watchdog_allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}