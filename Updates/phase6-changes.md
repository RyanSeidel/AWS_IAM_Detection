# Phase 6: Changes on `task-11-console-dashboard`

A walkthrough of everything changed on this branch, so you can review it before
committing. For each file, the explanation comes first and the code follows.

**Status:**
- Nothing is committed yet.
- Nothing is deployed to AWS yet. Run `terraform apply` in `main/` to create it.
- `terraform validate` passes.
- All 37 local tests pass.

| File | Change |
|---|---|
| [main/dashboard.tf](../main/dashboard.tf) | New: dashboard, baseline widget Lambda, analyst policy and group |
| [main/eventbridge.tf](../main/eventbridge.tf) | 1 line: detector log retention 7 → 30 days |
| [lambda/baseline_widget.py](../lambda/baseline_widget.py) | New: "What's normal" panel |
| [tests/test_baseline_widget.py](../tests/test_baseline_widget.py) | New: 9 tests for the panel |
| [Updates/phase6-plan.md](phase6-plan.md) | New: the revised Phase 6 plan (not repeated here) |

**How it fits together:**

```
Detector Lambda ──logs one JSON line per event──► CloudWatch Logs ──► 7 alert widgets ─┐
Baseline table (DynamoDB) ──► baseline_widget Lambda ──► "What's normal" widget ───────┤
                                                                                        ▼
                         Admin / analyst ──AWS console login──► InsiderWatch dashboard
                         (IAM checks every request: admin rights or insider-threat-analyst)
```

---

## `main/dashboard.tf` (New file)

**What it is:** the Terraform for Task 11. It creates everything the security team
uses in the AWS console. Nobody needs a new login.

**What's in it, top to bottom:**
1. **`locals`:** `detector_logs` is the start of every log query. It points at the
   detector's log group and skips Lambda's own START/END/REPORT lines.
   `dashboard_url` is the console link to the dashboard.
2. **`aws_cloudwatch_dashboard.insiderwatch`:** the dashboard. It opens on the last 7 days
   and has 8 widgets:
   - 7 log widgets: alert count, events scored and highest score, the recent alerts
     table, alerts by identity, alerts by MITRE tactic, highest score per hour,
     and tampering events
   - 1 custom widget: "What's normal (baseline)"
3. **The baseline widget's Lambda:**
   - `archive_file`: zips `baseline_widget.py` together with `handler.py`
   - `aws_iam_role` and `aws_iam_role_policy`: it may only Query/Scan the baseline
     table and write its own logs
   - `aws_cloudwatch_log_group`
   - `aws_lambda_function`

   It's named `insiderwatch-*` so that deploying it doesn't trigger the watchdog's
   tampering alerts.
4. **`aws_iam_policy.analyst` (`insider-threat-analyst`):** read-only access to:
   - open the dashboard
   - query the detector logs
   - load the baseline widget
   - read the baseline table

   It grants nothing that can change or switch off the detector.
5. **`aws_iam_group.analysts` and its policy attachment:** you give someone access with
   `aws iam add-user-to-group --group-name insider-threat-analysts --user-name <name>`.
6. **Outputs:** `dashboard_url` and `analyst_policy_arn`.

**How access is checked:** there's no access-check code anywhere. Every time someone opens the
dashboard or a widget runs, AWS checks that person's IAM permissions and returns
AccessDenied if they aren't allowed.

```hcl
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
```

---

## `main/eventbridge.tf` (Changed, 1 line)

**What changed:** the detector's logs are now kept for 30 days instead of 7.

**Why:** the dashboard's alert widgets read these logs. With 7 days, the dashboard
could only ever show the last week. The extra storage costs fractions of a cent.

```diff
diff --git a/main/eventbridge.tf b/main/eventbridge.tf
index 03a58f0..3bb8474 100644
--- a/main/eventbridge.tf
+++ b/main/eventbridge.tf
@@ -18,7 +18,7 @@ resource "aws_iam_role" "detector" {
 
 resource "aws_cloudwatch_log_group" "detector" {
   name              = "/aws/lambda/insider-threat-detector"
-  retention_in_days = 7
+  retention_in_days = 30 # the InsiderWatch dashboard reads these logs (dashboard.tf)
 }
 
 resource "aws_iam_role_policy" "detector" {
```

---

## `lambda/baseline_widget.py` (New file)

**What it is:** the Lambda behind the "What's normal (baseline)" panel. CloudWatch
calls it when the dashboard loads, and it returns HTML.

**How it works:**
1. `list_identities()` scans the baseline table for every identity that has a `profile`
   row. Each one becomes a button.
2. `handler()` picks the identity to show. That's the one whose button was clicked, or the
   first one when the dashboard first loads. It loads that identity's baseline with the
   detector's own `fetch_baseline`.
3. `render()` builds the panel: regions, IPs, a 24-hour strip and known APIs. Each
   section shows how many points a value outside the baseline adds.

**Why it imports `handler.py`:** the weights (+75 region, +25 IP, and so on) and the baseline
lookup come straight from the detector, so the panel can never show different numbers
from what the detector actually scores.

**Buttons:** each button is followed by a `<cwdb-action>` tag. That's CloudWatch's way of
saying "when clicked, call this Lambda again with `{"identity": ...}` and redraw the widget."

**Safety:** every value from the table goes through `html.escape`, so odd data can't
inject HTML into the dashboard.

```python
"""
"What's normal" panel for the InsiderWatch dashboard (CloudWatch custom widget).

CloudWatch calls this Lambda with the viewer's own credentials, so only
people allowed to invoke it (admins, insider-threat-analysts) see anything.
It returns HTML: one button per baselined identity, and the selected
identity's regions, IPs, hours and APIs with the points a new value adds.

Reads the baseline the same way the detector does (handler.fetch_baseline)
and uses the detector's weights, so the numbers can't drift from the scoring.
"""
import html
import json

import handler as detector

DOCS = """## What's normal (baseline)
Shows each identity's baseline from the insider-threat-baseline table, and
how many points a value outside it adds to an event's score.
"""


def list_identities():
    """Every identity with a baseline profile, sorted by display name."""
    table = detector.dynamodb.Table(detector.TABLE_NAME)
    kwargs = {"ProjectionExpression": "#i, facet", "ExpressionAttributeNames": {"#i": "identity"}}
    identities = []
    while True:
        page = table.scan(**kwargs)
        identities += [i["identity"] for i in page.get("Items", []) if i.get("facet") == "profile"]
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return sorted(identities, key=short_name)


def short_name(arn):
    """'arn:aws:iam::123:user/dana-test' -> 'dana-test', 'arn:aws:iam::123:root' -> 'root'."""
    return arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]


def hour_range(hours):
    """'13:00–23:00 UTC': from the first active hour to the end of the last one."""
    if not hours:
        return "none recorded"
    return f"{min(hours):02d}:00–{max(hours) + 1:02d}:00 UTC"


def chips(values, empty="none recorded"):
    if not values:
        return f'<span style="opacity:.6">{empty}</span>'
    return " ".join(
        f'<span style="display:inline-block;margin:2px;padding:2px 8px;border-radius:10px;'
        f'border:1px solid #8fbf9f;background:rgba(46,160,67,.12)">{html.escape(str(v))}</span>'
        for v in sorted(values)
    )


def hour_strip(active):
    cells = []
    for h in range(24):
        on = h in active
        style = ("background:#3b6fd8;color:#fff" if on
                 else "background:rgba(128,128,128,.15);opacity:.6")
        cells.append(f'<span style="display:inline-block;width:3.6%;margin:1px;padding:3px 0;'
                     f'text-align:center;border-radius:3px;{style}">{h}</span>')
    return "".join(cells)


def section(title, body, rule):
    return (f'<div style="margin:10px 0"><b>{title}</b><div style="margin:4px 0">{body}</div>'
            f'<div style="font-size:12px;opacity:.75">{rule}</div></div>')


def identity_buttons(identities, selected, endpoint):
    out = []
    for arn in identities:
        cls = "btn btn-primary" if arn == selected else "btn"
        out.append(f'<a class="{cls}" style="margin:2px">{html.escape(short_name(arn))}</a>'
                   f'<cwdb-action action="call" endpoint="{html.escape(endpoint)}" display="widget">'
                   f'{html.escape(json.dumps({"identity": arn}))}</cwdb-action>')
    return " ".join(out)


def render(identities, selected, profile, endpoint):
    top = identity_buttons(identities, selected, endpoint)
    if not selected:
        return top + "<p>No baselines yet. Run helpers/seed_baseline.py.</p>"

    header = f'<p style="margin:8px 0 0">Baseline for <code>{html.escape(selected)}</code></p>'
    if profile is None:
        return top + header + (f"<p>No baseline for this identity. Any event from it "
                               f"scores +{detector.WEIGHT_UNKNOWN_IDENTITY}.</p>")

    return top + header + "".join([
        section("Regions", chips(profile["known_regions"]),
                f"Any other region: <b>+{detector.WEIGHT_NEW_REGION}</b>, which alerts on its own "
                f"(threshold {detector.ALERT_THRESHOLD})."),
        section("IP addresses", chips(profile["known_ips"]),
                f"A new IP: <b>+{detector.WEIGHT_NEW_IP}</b>. IPv6 is compared by its /64 network."),
        section(f"Active hours · {hour_range(profile['normal_hours'])}",
                hour_strip(profile["normal_hours"]),
                f"Activity in a grey hour: <b>+{detector.WEIGHT_UNUSUAL_HOUR}</b>."),
        section(f"API calls ({len(profile['known_apis'])})", chips(profile["known_apis"]),
                f"An API not in this list: <b>+{detector.WEIGHT_NEW_API}</b>. A high-risk API adds "
                f"<b>+{detector.WEIGHT_HIGH_RISK_API}</b> (tampering <b>+{detector.WEIGHT_DEFENSE_EVASION}</b>) "
                f"even if it's in the list."),
    ])


def handler(event, context):
    if event.get("describe"):
        return DOCS

    identities = list_identities()
    selected = event.get("identity") or (identities[0] if identities else None)
    profile = detector.fetch_baseline(selected) if selected else None
    return render(identities, selected, profile, context.invoked_function_arn)
```

---

## `tests/test_baseline_widget.py` (New file)

**What it is:** 9 local tests for the widget. No AWS account is needed. It uses the same
fake-boto3 setup as `tests/test_handler.py`.

**What they check:**
- Only `profile` rows become identities, and multi-page scans are followed.
- The panel shows the baseline values and the detector's real weights.
- There's one button per identity, each calling back with its own ARN, and the selected one is highlighted.
- An identity with no baseline explains the +40 unknown-identity points.
- An empty table shows a "No baselines yet" message.
- HTML in the data is escaped.
- `describe` returns the widget docs, and clicking a button switches identity.
- Short names: `user/dana-test` becomes `dana-test`, and the root ARN becomes `root`.

**Run them:** `python -m unittest -v tests/test_baseline_widget.py`. All 9 pass, and so do
the existing 28 tests in `test_handler.py` and `test_simulate_attack.py`.

```python
"""
Local tests for lambda/baseline_widget.py. No AWS account or boto3 needed.

Run from the repo root:
    python3 -m unittest -v tests/test_baseline_widget.py
"""
import os
import sys
import unittest
from unittest import mock

# Same setup as tests/test_handler.py: env vars and a fake boto3 before import
os.environ.setdefault("ALERT_TOPIC", "arn:aws:sns:us-east-1:000000000000:test-topic")
os.environ.setdefault("BASELINE_TABLE", "test-baseline")
fake_boto3 = mock.MagicMock()
sys.modules["boto3"] = fake_boto3
sys.modules["boto3.dynamodb"] = fake_boto3.dynamodb
sys.modules["boto3.dynamodb.conditions"] = fake_boto3.dynamodb.conditions

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
import baseline_widget as widget  # noqa: E402

DANA = "arn:aws:iam::123456789012:user/dana-test"
RENCY = "arn:aws:iam::123456789012:user/rency.dev"
ENDPOINT = "arn:aws:lambda:us-east-1:123456789012:function:insiderwatch-baseline-widget"
PROFILE = {
    "known_regions": {"us-east-1"},
    "known_apis": {"s3:PutObject", "ec2:CreateTags"},
    "normal_hours": {13, 14, 22},
    "known_ips": {"203.0.113.24"},
}


def fake_table(pages):
    table = mock.MagicMock()
    table.scan.side_effect = pages
    return table


class ListIdentities(unittest.TestCase):
    def test_keeps_only_profiles_and_follows_pages(self):
        table = fake_table([
            {"Items": [{"identity": RENCY, "facet": "profile"}, {"identity": RENCY, "facet": "other"}],
             "LastEvaluatedKey": {"identity": RENCY}},
            {"Items": [{"identity": DANA, "facet": "profile"}]},
        ])
        with mock.patch.object(widget.detector.dynamodb, "Table", return_value=table):
            self.assertEqual(widget.list_identities(), [DANA, RENCY])  # sorted by short name
        self.assertEqual(table.scan.call_count, 2)


class Render(unittest.TestCase):
    def test_shows_baseline_and_detector_weights(self):
        out = widget.render([DANA], DANA, PROFILE, ENDPOINT)
        for text in ["us-east-1", "203.0.113.24", "s3:PutObject", "13:00–23:00 UTC",
                     f"+{widget.detector.WEIGHT_NEW_REGION}", f"+{widget.detector.WEIGHT_NEW_IP}",
                     f"+{widget.detector.WEIGHT_UNUSUAL_HOUR}", f"+{widget.detector.WEIGHT_NEW_API}"]:
            self.assertIn(text, out)

    def test_one_button_per_identity_calls_back_with_its_arn(self):
        out = widget.render([DANA, RENCY], DANA, PROFILE, ENDPOINT)
        self.assertEqual(out.count("<cwdb-action"), 2)
        self.assertIn(f'endpoint="{ENDPOINT}"', out)
        self.assertIn("rency.dev", out)
        self.assertIn('class="btn btn-primary"', out)  # the selected one

    def test_identity_without_profile_explains_unknown_identity_points(self):
        out = widget.render([DANA], DANA, None, ENDPOINT)
        self.assertIn(f"+{widget.detector.WEIGHT_UNKNOWN_IDENTITY}", out)

    def test_empty_table(self):
        self.assertIn("No baselines yet", widget.render([], None, None, ENDPOINT))

    def test_values_are_html_escaped(self):
        profile = dict(PROFILE, known_apis={"<script>x</script>"})
        out = widget.render([DANA], DANA, profile, ENDPOINT)
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)


class Handler(unittest.TestCase):
    def context(self):
        return mock.MagicMock(invoked_function_arn=ENDPOINT)

    def test_describe_returns_docs(self):
        self.assertEqual(widget.handler({"describe": True}, self.context()), widget.DOCS)

    def test_defaults_to_first_identity_then_uses_clicked_one(self):
        with mock.patch.object(widget, "list_identities", return_value=[DANA, RENCY]), \
             mock.patch.object(widget.detector, "fetch_baseline", return_value=PROFILE) as fetch:
            widget.handler({}, self.context())
            fetch.assert_called_with(DANA)
            widget.handler({"identity": RENCY}, self.context())
            fetch.assert_called_with(RENCY)


class ShortName(unittest.TestCase):
    def test_user_and_root(self):
        self.assertEqual(widget.short_name(DANA), "dana-test")
        self.assertEqual(widget.short_name("arn:aws:iam::123456789012:root"), "root")


if __name__ == "__main__":
    unittest.main()
```

---

## How to deploy and check it

1. In `main/`, run:
   `terraform apply -var="demo_user=true" -var="alert_email=you@example.com"`
   Expect the new dashboard resources, plus 1 change (the log retention).
2. Open the `dashboard_url` output. The first time, CloudWatch asks to run the
   widget's Lambda. Choose **Allow always**.
3. Run `python helpers/simulate_attack.py secret-theft`. The alert should appear in
   "Recent alerts" within about 2 minutes.
4. Click each identity button in "What's normal" and check that the baseline matches what was seeded.
5. Run `aws cloudwatch get-dashboard --dashboard-name InsiderWatch --profile dana-test`.
   It should return AccessDenied, which shows IAM is doing the checking.

## Not done yet

- The per-reason points breakdown (+40, +75, ...) on alerts needs Task 8 (`scoring.py`).
- Add the alerts table to the analyst policy once Task 9 creates it.
- The `insiderwatch.py` CLI (the rest of Task 12).
