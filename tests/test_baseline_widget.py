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
