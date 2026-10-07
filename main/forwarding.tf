# Cross-region forwarding.
#
# CloudTrail delivers each API call to EventBridge in the region where it
# happened, and the detector rule only exists in us-east-1. Each other enabled
# region gets a forwarding rule (same pattern) that sends matches to the
# us-east-1 default bus, where the existing rule hands them to the one Lambda.
#
# No forwarding rule exists in us-east-1, so forwarded events can't loop.

data "aws_regions" "enabled" {}

locals {
  home_bus_arn      = "arn:aws:events:us-east-1:${data.aws_caller_identity.current.account_id}:event-bus/default"
  forwarded_regions = setsubtract(data.aws_regions.enabled.names, ["us-east-1"])
}

resource "aws_iam_role" "forwarder" {
  name = "insider-threat-forwarder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "forwarder" {
  role = aws_iam_role.forwarder.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["events:PutEvents"]
      Resource = local.home_bus_arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "forward" {
  for_each = local.forwarded_regions

  region        = each.key
  name          = "insider-threat-forward-to-us-east-1"
  event_pattern = local.risky_event_pattern
}

resource "aws_cloudwatch_event_target" "forward" {
  for_each = local.forwarded_regions

  region   = each.key
  rule     = aws_cloudwatch_event_rule.forward[each.key].name
  arn      = local.home_bus_arn
  role_arn = aws_iam_role.forwarder.arn
}

resource "aws_cloudwatch_event_rule" "watchdog_forward" {
  for_each = local.forwarded_regions

  region        = each.key
  name          = "insider-threat-watchdog-forward"
  description   = "Forward tampering events targeting regional forwarders back to us-east-1"
  
  event_pattern = jsonencode({
    "source": ["aws.events"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["DisableRule", "RemoveTargets", "DeleteRule"],
      "requestParameters": {
        "name": [{ "prefix": "insider-threat" }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "watchdog_forward_target" {
  for_each = local.forwarded_regions

  region   = each.key
  rule     = aws_cloudwatch_event_rule.watchdog_forward[each.key].name
  arn      = local.home_bus_arn
  role_arn = aws_iam_role.forwarder.arn
}