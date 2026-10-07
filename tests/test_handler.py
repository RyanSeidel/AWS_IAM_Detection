"""
Local tests for lambda/handler.py. No AWS account or boto3 needed.

Run from the repo root:
    python3 -m unittest -v tests/test_handler.py

How it works:
- A fake 'boto3' is put in place before handler.py is imported, so nothing
  ever talks to AWS.
- fetch_baseline is replaced with a function returning a profile we choose.
- sns_client is replaced with a mock, so we can check whether an alert was sent.
- handler() prints one JSON line at the end; we read it to get the score.
"""
import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

# 1. Environment variables handler.py reads at import time
os.environ.setdefault("ALERT_TOPIC", "arn:aws:sns:us-east-1:000000000000:test-topic")
os.environ.setdefault("BASELINE_TABLE", "test-baseline")

# 2. Fake boto3, so the import works without AWS
fake_boto3 = mock.MagicMock()
sys.modules["boto3"] = fake_boto3
sys.modules["boto3.dynamodb"] = fake_boto3.dynamodb
sys.modules["boto3.dynamodb.conditions"] = fake_boto3.dynamodb.conditions

# 3. 'lambda' is a Python keyword, so add the folder to the path and import the file directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
import handler  # noqa: E402

ACCOUNT = "123456789012"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/test.user"
ROOT_ARN = f"arn:aws:iam::{ACCOUNT}:root"
HOME_IP = "203.0.113.10"

# What test.user normally does: us-east-1, around 20:00 UTC, from home, two APIs
NORMAL_PROFILE = {
    "known_regions": {"us-east-1"},
    "known_apis": {"s3:CreateBucket", "ssm:PutParameter"},
    "normal_hours": {20},
    "known_ips": {HOME_IP},
}


def make_event(source="s3", name="CreateBucket", region="us-east-1",
               ip=HOME_IP, time="2026-10-07T20:15:00Z",
               identity_type="IAMUser", arn=USER_ARN, error_code=None):
    """Builds an EventBridge event shaped like a real CloudTrail record."""
    detail = {
        "eventSource": f"{source}.amazonaws.com",
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "eventTime": time,
        "userIdentity": {"type": identity_type, "arn": arn},
    }
    if error_code:
        detail["errorCode"] = error_code
    return {"detail-type": "AWS API Call via CloudTrail", "detail": detail}


def run(event, profile=NORMAL_PROFILE, baseline_error=None):
    """
    Runs handler() with a chosen baseline.
    Returns (result_dict, alert_sent).
    profile=None means 'identity has no baseline'.
    baseline_error=Exception(...) simulates DynamoDB failing.
    """
    def fake_fetch(_identity):
        if baseline_error:
            raise baseline_error
        return profile

    sns = mock.MagicMock()
    out = io.StringIO()
    with mock.patch.object(handler, "fetch_baseline", fake_fetch), \
         mock.patch.object(handler, "sns_client", sns), \
         contextlib.redirect_stdout(out):
        handler.handler(event, None)

    last_line = out.getvalue().strip().splitlines()[-1]
    return json.loads(last_line), sns.publish.called


# ----------------------------------------------------------------------
# Current behaviour. These should all pass on the code as it is today.
# ----------------------------------------------------------------------
class CurrentBehaviour(unittest.TestCase):

    def test_normal_call_scores_zero(self):
        result, alerted = run(make_event())
        self.assertEqual(result["score"], 0)
        self.assertFalse(alerted)

    def test_stolen_key_pattern_alerts(self):
        # Secret read, new API, new region, 3am, new IP: 40+20+35+25+25
        event = make_event(source="ssm", name="GetParameter", region="eu-west-1",
                           ip="198.51.100.7", time="2026-10-07T03:00:00Z")
        result, alerted = run(event)
        self.assertEqual(result["score"], 145)
        self.assertTrue(alerted)

    def test_unknown_identity_harmless_call_no_alert(self):
        result, alerted = run(make_event(), profile=None)
        self.assertEqual(result["score"], 40)
        self.assertFalse(alerted)

    def test_unknown_identity_high_risk_call_alerts(self):
        result, alerted = run(make_event(source="iam", name="CreateAccessKey"), profile=None)
        self.assertEqual(result["score"], 80)
        self.assertTrue(alerted)

    def test_stop_logging_alerts_on_its_own(self):
        profile = dict(NORMAL_PROFILE, known_apis={"cloudtrail:StopLogging"})
        result, alerted = run(make_event(source="cloudtrail", name="StopLogging"), profile=profile)
        self.assertGreaterEqual(result["score"], handler.ALERT_THRESHOLD)
        self.assertTrue(alerted)

    def test_baseline_failure_fails_closed(self):
        result, alerted = run(make_event(), baseline_error=Exception("DynamoDB down"))
        self.assertGreaterEqual(result["score"], handler.ALERT_THRESHOLD)
        self.assertTrue(alerted)

    def test_lambda_version_suffix_is_stripped(self):
        result, _ = run(make_event(source="lambda", name="CreateFunction20150331"))
        self.assertEqual(result["api"], "lambda:CreateFunction")


# ----------------------------------------------------------------------
# Your tasks. Skipped for now; remove the @unittest.skip line when you
# implement each task, then run the tests again.
# ----------------------------------------------------------------------
class Task4RootAlwaysAlerts(unittest.TestCase):

    @unittest.skip("Task 4 not implemented yet")
    def test_root_matching_its_profile_still_alerts(self):
        # Root doing a completely normal call for root: would score 0 today
        event = make_event(identity_type="Root", arn=ROOT_ARN)
        result, alerted = run(event)
        self.assertGreaterEqual(result["score"], handler.ALERT_THRESHOLD)
        self.assertTrue(alerted)
        self.assertTrue(any("root" in r.lower() for r in result["reasons"]))


class Task3NewHighRiskApis(unittest.TestCase):

    NEW_APIS = [
        ("iam", "CreateUser"),
        ("iam", "CreatePolicyVersion"),
        ("iam", "SetDefaultPolicyVersion"),
        ("iam", "AddUserToGroup"),
        ("iam", "UpdateAssumeRolePolicy"),
        ("iam", "DeactivateMFADevice"),
        ("ec2", "AuthorizeSecurityGroupIngress"),
    ]

    @unittest.skip("Task 3 not implemented yet")
    def test_each_new_api_is_high_risk(self):
        for source, name in self.NEW_APIS:
            with self.subTest(api=f"{source}:{name}"):
                self.assertIn(f"{source}:{name}", handler.HIGH_RISK_APIS)

    @unittest.skip("Task 3 not implemented yet")
    def test_unknown_user_create_user_alerts(self):
        # Board's done-when: 40 (unknown) + 40 (high risk) = 80
        result, alerted = run(make_event(source="iam", name="CreateUser"), profile=None)
        self.assertEqual(result["score"], 80)
        self.assertTrue(alerted)


class Task5DeniedCalls(unittest.TestCase):

    @unittest.skip("Task 5 not implemented yet")
    def test_access_denied_adds_points_with_reason(self):
        allowed, _ = run(make_event())
        denied, _ = run(make_event(error_code="AccessDenied"))
        self.assertEqual(denied["score"] - allowed["score"], 25)
        self.assertTrue(any("denied" in r.lower() for r in denied["reasons"]))

    @unittest.skip("Task 5 not implemented yet")
    def test_ec2_unauthorized_operation_counts(self):
        for code in ["UnauthorizedOperation", "Client.UnauthorizedOperation"]:
            with self.subTest(code=code):
                result, _ = run(make_event(source="ec2", name="RunInstances", error_code=code))
                self.assertTrue(any("denied" in r.lower() for r in result["reasons"]))

    @unittest.skip("Task 5 not implemented yet")
    def test_other_errors_do_not_count(self):
        result, _ = run(make_event(error_code="ThrottlingException"))
        self.assertEqual(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
