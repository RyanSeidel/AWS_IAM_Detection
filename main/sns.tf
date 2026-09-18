resource "aws_sns_topic" "alerts" {
  name = "insider-threat-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

variable "alert_email" {
  type = string
}

output "alert_topic" {
  value = aws_sns_topic.alerts.arn
}
