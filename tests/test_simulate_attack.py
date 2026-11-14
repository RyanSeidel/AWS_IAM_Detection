"""
Local tests for the persistence steps (2a-2e) in helpers/simulate_attack.py.
No AWS account, boto3 or dana-test profile needed.

Run from the repo root:
    python3 -m unittest -v tests/test_simulate_attack.py

How it works:
- Fake 'boto3' and 'botocore' modules are put in place before the script is
  imported, so nothing talks to AWS.
- A fake ctx (Context) hands out mock IAM/STS clients whose answers we choose.
"""
import contextlib
import io
import os
import sys
import types
import unittest
from unittest import mock


# Fake botocore.exceptions.ClientError with the same shape as the real one
class FakeClientError(Exception):
    def __init__(self, code, operation="Call"):
        self.response = {"Error": {"Code": code, "Message": code}}
        super().__init__(f"An error occurred ({code}) when calling the {operation} operation")


sys.modules["boto3"] = mock.MagicMock()
botocore = types.ModuleType("botocore")
botocore_exceptions = types.ModuleType("botocore.exceptions")
botocore_exceptions.ClientError = FakeClientError
sys.modules["botocore"] = botocore
sys.modules["botocore.exceptions"] = botocore_exceptions

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
import simulate_attack as sim  # noqa: E402


def make_ctx(iam=None, sts=None):
    """A stand-in for sim.Context with mock clients for dana and admin."""
    ctx = mock.MagicMock()
    ctx.created_key_ids = []
    ctx.created_login_profile = False
    ctx.dana_password = None
    iam = iam or mock.MagicMock()
    sts = sts or mock.MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    ctx.dana.client.side_effect = lambda name, **kw: {"iam": iam, "sts": sts}[name]
    ctx.admin_iam = mock.MagicMock()
    ctx.admin.client.side_effect = lambda name, **kw: ctx.admin_iam
    return ctx, iam


def step(step_id):
    return next(s for s in sim.STEPS if s.id == step_id)


def quiet(fn, *args):
    """Runs fn, returns (result, printed_text)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = fn(*args)
    return result, out.getvalue()


class Wiring(unittest.TestCase):

    def test_every_persistence_step_has_attack_code(self):
        for step_id in ["2a", "2b", "2c", "2d", "2e"]:
            with self.subTest(step=step_id):
                self.assertIsNotNone(step(step_id).run)


class Step2aBackdoorKey(unittest.TestCase):

    def test_creates_key_and_records_it_for_cleanup(self):
        ctx, iam = make_ctx()
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [{"AccessKeyId": "AKIA_EXISTING"}]}
        iam.create_access_key.return_value = {"AccessKey": {
            "AccessKeyId": "AKIA_NEW", "SecretAccessKey": "SUPER-SECRET-VALUE"}}
        result, printed = quiet(sim.create_backdoor_key, ctx, step("2a"))
        self.assertEqual(result, "ok")
        self.assertEqual(ctx.created_key_ids, ["AKIA_NEW"])
        iam.create_access_key.assert_called_once_with(UserName="dana-test")

    def test_never_prints_the_secret(self):
        ctx, iam = make_ctx()
        iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        iam.create_access_key.return_value = {"AccessKey": {
            "AccessKeyId": "AKIA_NEW", "SecretAccessKey": "SUPER-SECRET-VALUE"}}
        _, printed = quiet(sim.create_backdoor_key, ctx, step("2a"))
        self.assertNotIn("SUPER-SECRET-VALUE", printed)

    def test_skips_when_dana_already_has_two_keys(self):
        ctx, iam = make_ctx()
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [{}, {}]}
        result, _ = quiet(sim.create_backdoor_key, ctx, step("2a"))
        self.assertEqual(result, "skipped")
        iam.create_access_key.assert_not_called()


class Step2bBackdoorUser(unittest.TestCase):

    def test_denied_create_user_is_the_expected_outcome(self):
        ctx, iam = make_ctx()
        iam.create_user.side_effect = FakeClientError("AccessDenied", "CreateUser")
        result, printed = quiet(sim.create_backdoor_user, ctx, step("2b"))
        self.assertEqual(result, "ok")
        self.assertIn("AccessDenied", printed)
        ctx.admin_iam.delete_user.assert_not_called()

    def test_deletes_user_if_policy_wrongly_allowed_it(self):
        ctx, iam = make_ctx()  # create_user succeeds: dana's policy is too broad
        _, printed = quiet(sim.create_backdoor_user, ctx, step("2b"))
        ctx.admin_iam.delete_user.assert_called_once_with(UserName="svc-backup")
        self.assertIn("too broad", printed)


class Step2cConsolePassword(unittest.TestCase):

    def test_creates_password_and_records_it_for_cleanup(self):
        ctx, iam = make_ctx()
        result, _ = quiet(sim.create_console_password, ctx, step("2c"))
        self.assertEqual(result, "ok")
        self.assertTrue(ctx.created_login_profile)
        self.assertTrue(ctx.dana_password)
        kwargs = iam.create_login_profile.call_args.kwargs
        self.assertEqual(kwargs["UserName"], "dana-test")
        self.assertEqual(kwargs["Password"], ctx.dana_password)

    def test_new_password_each_run(self):
        ctx1, _ = make_ctx()
        ctx2, _ = make_ctx()
        quiet(sim.create_console_password, ctx1, step("2c"))
        quiet(sim.create_console_password, ctx2, step("2c"))
        self.assertNotEqual(ctx1.dana_password, ctx2.dana_password)

    def test_skips_if_leftover_password_exists(self):
        ctx, iam = make_ctx()
        iam.create_login_profile.side_effect = FakeClientError("EntityAlreadyExists")
        result, _ = quiet(sim.create_console_password, ctx, step("2c"))
        self.assertEqual(result, "skipped")
        self.assertFalse(ctx.created_login_profile)

    def test_other_errors_are_not_swallowed(self):
        ctx, iam = make_ctx()
        iam.create_login_profile.side_effect = FakeClientError("PasswordPolicyViolation")
        with self.assertRaises(FakeClientError):
            quiet(sim.create_console_password, ctx, step("2c"))


class Steps2d2eManualSignIns(unittest.TestCase):

    def test_skip_without_a_password(self):
        ctx, _ = make_ctx()
        for fn in (sim.console_login_wrong_password, sim.console_login_no_mfa):
            with self.subTest(fn=fn.__name__):
                result, _ = quiet(fn, ctx, step("2d"))
                self.assertEqual(result, "skipped")

    def test_2e_shows_url_and_password_then_waits(self):
        ctx, _ = make_ctx()
        ctx.dana_password = "pw-123"
        with mock.patch("builtins.input", return_value="") as fake_input:
            result, printed = quiet(sim.console_login_no_mfa, ctx, step("2e"))
        self.assertEqual(result, "ok")
        self.assertIn("https://123456789012.signin.aws.amazon.com/console", printed)
        self.assertIn("pw-123", printed)
        fake_input.assert_called_once()

    def test_2d_does_not_reveal_the_real_password(self):
        ctx, _ = make_ctx()
        ctx.dana_password = "pw-123"
        with mock.patch("builtins.input", return_value=""):
            _, printed = quiet(sim.console_login_wrong_password, ctx, step("2d"))
        self.assertNotIn("pw-123", printed)


if __name__ == "__main__":
    unittest.main()
