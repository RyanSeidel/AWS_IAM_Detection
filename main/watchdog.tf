resource "aws_cloudwatch_event_rule" "watchdog_direct" {
  name        = "insider-threat-watchdog"
  description = "Dead-man switch: Alerts SNS directly if the detector is disabled/deleted"

  event_pattern = jsonencode({
    "source": ["aws.events", "aws.lambda", "aws.sns"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      # Lambda event names carry an API version suffix in CloudTrail
      # (e.g. DeleteFunction20150331), so those are prefix matches.
      "eventName": [
        "DisableRule", "RemoveTargets", "DeleteRule", "Unsubscribe",
        { "prefix": "DeleteFunction" },
        { "prefix": "UpdateFunctionCode" },
        { "prefix": "UpdateFunctionConfiguration" },
        { "prefix": "PutFunctionConcurrency" },
        { "prefix": "DeleteFunctionConcurrency" }
      ],
      # DisableRule/DeleteRule use "name", RemoveTargets uses "rule".
      # functionName may be a bare name or a full ARN, hence the wildcard.
      "requestParameters": {
        "$or": [
          { "name": [{ "prefix": "insider-threat" }] },
          { "rule": [{ "prefix": "insider-threat" }] },
          { "functionName": [{ "wildcard": "*insider-threat*" }] },
          { "subscriptionArn": [{ "wildcard": "*insider-threat*" }] }
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

# Second dead-man switch for the detector's DynamoDB tables. If the baseline
# table is deleted the Lambda still alerts (it fails closed), but this emails
# even if the Lambda itself is broken. The tables only exist in us-east-1, so
# no regional forwarding is needed. UpdateTable also fires when protect_data
# or capacity is changed through Terraform; that alert is expected.
resource "aws_cloudwatch_event_rule" "watchdog_tables" {
  name        = "insider-threat-watchdog-tables"
  description = "Alerts SNS directly on deletes or protection changes to the detector's tables"

  event_pattern = jsonencode({
    "source": ["aws.dynamodb"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": [
        "DeleteTable", "UpdateTable", "UpdateContinuousBackups",
        "DeleteBackup", "PutResourcePolicy", "DeleteResourcePolicy"
      ],
      # Table calls use "tableName"; backup and resource-policy calls carry
      # the table inside an ARN.
      "requestParameters": {
        "$or": [
          { "tableName": [{ "prefix": "insider-threat" }] },
          { "backupArn": [{ "wildcard": "*table/insider-threat*" }] },
          { "resourceArn": [{ "wildcard": "*table/insider-threat*" }] }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "watchdog_tables_sns" {
  rule      = aws_cloudwatch_event_rule.watchdog_tables.name
  target_id = "WatchdogTablesToSNS"
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