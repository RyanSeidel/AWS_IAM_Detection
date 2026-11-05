# Task 11: the InsiderWatch dashboard, inside the AWS console.
#
# Admins open it with the console login they already have: CloudWatch ->
# Dashboards -> InsiderWatch. No separate website or login. The log widgets
# query the one JSON line the detector logs per scored event (lambda/handler.py);
# the "What's normal" panel is a custom widget (lambda/baseline_widget.py).
#
# Who can see it is decided by IAM. Admins already can; anyone else needs the
# insider-threat-analyst policy, granted by adding them to the
# insider-threat-analysts group. The policy is read-only, so analysts can watch
# alerts but can't change or switch off the detector.

locals {
  # Every query starts here. ispresent(score) skips Lambda's START/END/REPORT lines.
  detector_logs = "SOURCE '${aws_cloudwatch_log_group.detector.name}' | filter ispresent(score)"
  dashboard_url = "https://us-east-1.console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards/dashboard/InsiderWatch"
}

resource "aws_cloudwatch_dashboard" "insiderwatch" {
  dashboard_name = "InsiderWatch"

  dashboard_body = jsonencode({
    start = "-P7D" # opens on the last 7 days
    widgets = [
      {
        type = "log", x = 0, y = 0, width = 12, height = 3
        properties = {
          title  = "Alerts (score 75 or more)"
          region = "us-east-1"
          view   = "table"
          query  = "${local.detector_logs} | filter score >= 75 | stats count(*) as alerts"
        }
      },
      {
        type = "log", x = 12, y = 0, width = 12, height = 3
        properties = {
          title  = "Events scored"
          region = "us-east-1"
          view   = "table"
          query  = "${local.detector_logs} | stats count(*) as events_scored, max(score) as highest_score"
        }
      },
      {
        type = "log", x = 0, y = 3, width = 24, height = 8
        properties = {
          title  = "Recent alerts"
          region = "us-east-1"
          view   = "table"
          query  = "${local.detector_logs} | filter score >= 75 | fields @timestamp, identity, api, region, source_ip, score, tactics.0 as tactic, reasons.0 as top_reason | sort @timestamp desc | limit 50"
        }
      },
      {
        type = "log", x = 0, y = 11, width = 12, height = 6
        properties = {
          title  = "Alerts by identity"
          region = "us-east-1"
          view   = "bar"
          query  = "${local.detector_logs} | filter score >= 75 | stats count(*) as alerts by identity | sort alerts desc"
        }
      },
      {
        type = "log", x = 12, y = 11, width = 12, height = 6
        properties = {
          title  = "Alerts by MITRE tactic"
          region = "us-east-1"
          view   = "pie"
          query  = "${local.detector_logs} | filter score >= 75 | stats count(*) as alerts by tactics.0"
        }
      },
      {
        type = "log", x = 0, y = 17, width = 12, height = 6
        properties = {
          title  = "Highest score per hour"
          region = "us-east-1"
          view   = "timeSeries"
          query  = "${local.detector_logs} | stats max(score) as highest_score by bin(1h)"
        }
      },
      {
        type = "log", x = 12, y = 17, width = 12, height = 6
        properties = {
          title  = "Tampering with logging or the detector"
          region = "us-east-1"
          view   = "table"
          query  = "${local.detector_logs} | filter @message like /tamper|StopLogging|DeleteTrail|DeleteDetector/ | fields @timestamp, identity, api, region, score | sort @timestamp desc"
        }
      },
      {
        type = "custom", x = 0, y = 23, width = 24, height = 10
        properties = {
          title    = "What's normal (baseline)"
          endpoint = aws_lambda_function.baseline_widget.arn
          updateOn = { refresh = true, resize = false, timeRange = false }
        }
      }
    ]
  })
}

# The "What's normal" panel is a custom widget: a small Lambda that reads the
# baseline table and returns HTML. It imports handler.py for fetch_baseline and
# the weights, so both files go in its zip.
#
# Named insiderwatch-*, not insider-threat-*, so deploying it doesn't trip the
# watchdog and tamper scoring, which watch for changes to insider-threat-* Lambdas.
data "archive_file" "baseline_widget" {
  type        = "zip"
  output_path = "${path.module}/baseline_widget.zip"

  source {
    content  = file("${path.module}/../lambda/baseline_widget.py")
    filename = "baseline_widget.py"
  }
  source {
    content  = file("${path.module}/../lambda/handler.py")
    filename = "handler.py"
  }
}

resource "aws_iam_role" "baseline_widget" {
  name = "insiderwatch-baseline-widget"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "baseline_widget" {
  name              = "/aws/lambda/insiderwatch-baseline-widget"
  retention_in_days = 7
}

# Read-only: it can list and read baselines, nothing else.
resource "aws_iam_role_policy" "baseline_widget" {
  role = aws_iam_role.baseline_widget.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.baseline_widget.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:Query", "dynamodb:Scan"]
        Resource = aws_dynamodb_table.baseline.arn
      }
    ]
  })
}

resource "aws_lambda_function" "baseline_widget" {
  function_name    = "insiderwatch-baseline-widget"
  role             = aws_iam_role.baseline_widget.arn
  handler          = "baseline_widget.handler"
  runtime          = "python3.13"
  filename         = data.archive_file.baseline_widget.output_path
  source_code_hash = data.archive_file.baseline_widget.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      BASELINE_TABLE = aws_dynamodb_table.baseline.name
      # handler.py reads this at import. The widget never publishes (no sns permission).
      ALERT_TOPIC = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.baseline_widget]
}

resource "aws_iam_policy" "analyst" {
  name        = "insider-threat-analyst"
  description = "Read-only access to InsiderWatch alerts, baselines and dashboard"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OpenDashboard"
        Effect   = "Allow"
        Action   = ["cloudwatch:GetDashboard"]
        Resource = aws_cloudwatch_dashboard.insiderwatch.dashboard_arn
      },
      {
        Sid      = "QueryDetectorLogs"
        Effect   = "Allow"
        Action   = ["logs:StartQuery", "logs:GetLogGroupFields"]
        Resource = "${aws_cloudwatch_log_group.detector.arn}:*"
      },
      {
        # These actions don't support resource-level permissions, so AWS requires "*".
        Sid    = "ListAndReadQueryResults"
        Effect = "Allow"
        Action = [
          "cloudwatch:ListDashboards",
          "logs:DescribeLogGroups",
          "logs:GetQueryResults",
          "logs:StopQuery",
          "logs:DescribeQueries"
        ]
        Resource = "*"
      },
      {
        # CloudWatch runs custom widgets with the viewer's credentials, so this
        # is what lets an analyst load the "What's normal" panel.
        Sid      = "LoadBaselineWidget"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.baseline_widget.arn
      },
      {
        # For helpers/insiderwatch.py (Task 12). Add the alerts table and
        # its "/index/*" here once Task 9 creates it.
        Sid      = "ReadTables"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:DescribeTable"]
        Resource = [aws_dynamodb_table.baseline.arn]
      }
    ]
  })
}

# Grant access through the group, never user by user:
#   aws iam add-user-to-group --group-name insider-threat-analysts --user-name <name>
resource "aws_iam_group" "analysts" {
  name = "insider-threat-analysts"
}

resource "aws_iam_group_policy_attachment" "analysts" {
  group      = aws_iam_group.analysts.name
  policy_arn = aws_iam_policy.analyst.arn
}

output "dashboard_url" {
  value = local.dashboard_url
}

output "analyst_policy_arn" {
  value = aws_iam_policy.analyst.arn
}
