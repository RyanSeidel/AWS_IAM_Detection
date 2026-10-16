"""
Task 7B: The attack simulator

commands: 
    python helpers/simulate_attack.py secret-theft
    python helpers/simulate_attack.py persistence
    python helpers/simulate_attack.py detector-off
    python helpers/simulate_attack.py mock-root
    python helpers/simulate_attack.py all          # every scenario, detector-off last

Run it from CloudShell with a dana-test profile there, so the new-IP and
odd-hour signals fire. Steps 1-3 use the dana-test profile; step 4 (mock-root)
uses your own admin profile. dana's baseline is reset before each run, so
every run starts from the same profile.
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import boto3
from botocore.exceptions import ClientError


# Important Globals 
ACCOUNT_REGION = "us-east-1"
LOG_GROUP = "/aws/lambda/insider-threat-detector"
DANA = "dana-test"
# The eu-west-1 forwarding rule dana is allowed to switch off (main/forwarding.tf).
# Never the us-east-1 main rule: if that stayed disabled the whole detector is off.
FWD_RULE = "insider-threat-forward-to-us-east-1"
FWD_REGION = "eu-west-1"
FULL_STATE = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
ENABLED_STATES = ("ENABLED", FULL_STATE)


def restore_full_state(ctx):
    """EnableRule turns the rule back to plain ENABLED, which drops read-only
    events. Put back the state Terraform set, keeping the same pattern
    (admin profile: dana can't call PutRule)."""
    ev = ctx.admin.client("events", region_name=FWD_REGION)
    rule = ev.describe_rule(Name=FWD_RULE)
    if rule["State"] != FULL_STATE:
        ev.put_rule(Name=FWD_RULE, EventPattern=rule["EventPattern"], State=FULL_STATE)
        print(f"   restored {FWD_RULE} ({FWD_REGION}) to {FULL_STATE}")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class Step:
    id: str     # the step label like what part exercis
    scenario: str   # what attack group
    what: str       # plain descript of attack
    exercises: str  # which tasks it follows
    expected: str                      # shown in the table, from the task card
    min_score: Optional[int]           # pass if the best matching log line scores >= this
    apis: list                         # handler 'api' values this step produces
    identity: str = DANA               # whose log lines belong to this step
    manual: bool = False
    run: Optional[Callable] = None     # set once the attack code is written
    result: dict = field(default_factory=dict)


def attack_does_not_exist(ctx, step):
    print(f"   [{step.id}] attack code not written yet, skipping")
    return "skipped"


STEPS = [
    # Scenario 1: secret theft
    Step(
        id="1a",
        scenario="secret-theft",
        what="probes 5 secrets she can't read (/prod/*)",
        exercises="Task 5",
        expected="+25 denied each; repeat bonus on the 5th",
        min_score=75,
        apis=["ssm:GetParameter"],
    ),
    Step(
        id="1b",
        scenario="secret-theft",
        what="ssm:GetParameter /demo/db-password in eu-west-1",
        exercises="baseline",
        expected="~145 on the card (~185 with new-region = 75), alert",
        min_score=75,
        apis=["ssm:GetParameter"],
    ),

    # Scenario 2: persistence
    Step(
        id="2a",
        scenario="persistence",
        what="iam:CreateAccessKey on herself",
        exercises="baseline",
        expected="~110, alert",
        min_score=75,
        apis=["iam:CreateAccessKey"],
    ),
    Step(
        id="2b",
        scenario="persistence",
        what="iam:CreateUser svc-backup, denied",
        exercises="Task 3 + Task 5",
        expected="+40 Persistence +25 denied, alert",
        min_score=75,
        apis=["iam:CreateUser"],
    ),
    Step(
        id="2c",
        scenario="persistence",
        what="iam:CreateLoginProfile on herself",
        exercises="baseline",
        expected="new API + IP + hour",
        min_score=None,
        apis=["iam:CreateLoginProfile"],
    ),
    Step(
        id="2d",
        scenario="persistence",
        what="console sign-in, WRONG password (browser)",
        exercises="Task 1",
        expected="failed login +25",
        min_score=None,
        apis=["signin:ConsoleLogin"],
        manual=True,
    ),
    Step(
        id="2e",
        scenario="persistence",
        what="console sign-in, right password, no MFA (browser)",
        exercises="Task 1",
        expected="no MFA +40, alert",
        min_score=75,
        apis=["signin:ConsoleLogin"],
        manual=True,
    ),

    #  Scenario 4: mock root 
    Step(
        id="4",
        scenario="mock-root",
        what="your admin user invokes the Lambda with a fake root event",
        exercises="Task 4",
        expected=">= ALERT_THRESHOLD, root reason",
        min_score=75,
        apis=["ssm:PutParameter"],
        identity=":root",
    ),

    # ---- Scenario 3: detector off ------------------------------------------
    # Always last in 'all': if re-enabling ever failed, nothing after it in
    # eu-west-1 would be detected.
    Step(
        id="3",
        scenario="detector-off",
        what="disables the eu-west-1 forwarding rule, re-enables it",
        exercises="Task 2",
        expected="alert + watchdog email",
        min_score=75,
        apis=["events:DisableRule"],
    ),
]

SCENARIOS = ["secret-theft", "persistence", "detector-off", "mock-root"]

# Create attack functions for the steps above!

DENIED_SECRETS = [
    "/prod/db-password",
    "/prod/api-key",
    "/prod/stripe-key",
    "/admin/root-creds",
    "/prod/jwt-secret",
]

def probe_denied_secrets(ctx, step):
    """1a: five GetParameter calls dana cannot make. AccessDenied is the point."""
    ssm = ctx.dana.client("ssm")  # us-east-1, so this step is not also a new region
    for name in DENIED_SECRETS:
        try:
            ssm.get_parameter(Name=name, WithDecryption=True)
            print(f"   unexpected success reading {name}")
        except ClientError as e:
            print(f"   denied {name}: {e.response['Error']['Code']}")
    return "ok"

def steal_demo_secret(ctx, step):
    """1b: the one secret dana can read, from a region she never uses."""
    ssm = ctx.dana.client("ssm", region_name="eu-west-1")
    try:
        value = ssm.get_parameter(Name="/demo/db-password", WithDecryption=True)
        print(f"   read /demo/db-password in eu-west-1 ({len(value['Parameter']['Value'])} chars)")
    except ClientError as e:
        print(f"   failed to read /demo/db-password: {e.response['Error']['Code']}")
    return "ok"

def detector_off(ctx, step):
    """3: disable only the eu-west-1 forwarding rule. The watchdog carries the event."""
    ev = ctx.dana.client("events", region_name=FWD_REGION)
    try:
        ev.disable_rule(Name=FWD_RULE)
        print(f"   {FWD_RULE} in {FWD_REGION} DISABLED, waiting for watchdog...")
        print("   check inbox for the watchdog alert")
        time.sleep(30)
    finally:
        ev.enable_rule(Name=FWD_RULE)
        restore_full_state(ctx)
        state = ev.describe_rule(Name=FWD_RULE)["State"]
        print(f"   forwarding rule state: {state}")
        if state not in ENABLED_STATES:
            raise RuntimeError("RE-ENABLE IT MANUALLY NOW")
    return "ok"

def mock_root(ctx, step):
    """4: your admin user invokes the Lambda directly with a fake root event."""
    account = ctx.admin.client("sts").get_caller_identity()["Account"]
    
    # Event matches Dana's profile perfectly, so only the Root identity triggers the alert.
    event = {
        "detail-type": "AWS API Call via CloudTrail", 
        "detail": {
            "eventName": "PutParameter", 
            "eventSource": "ssm.amazonaws.com",
            "awsRegion": "us-east-1", 
            "sourceIPAddress": "203.0.113.10",
            "eventTime": "2026-10-15T20:00:00Z",
            "userIdentity": {
                "type": "Root", 
                "arn": f"arn:aws:iam::{account}:root"
            }
        }
    }
    
    ctx.admin.client("lambda").invoke(
        FunctionName="insider-threat-detector",
        Payload=json.dumps(event)
    )
    print("   invoked Lambda directly with fake Root event")
    return "ok"

BACKDOOR_USER = "svc-backup"


def console_url(ctx):
    """The account's IAM-user console sign-in page."""
    account = ctx.dana.client("sts").get_caller_identity()["Account"]
    return f"https://{account}.signin.aws.amazon.com/console"


def create_backdoor_key(ctx, step):
    """2a: dana makes a second access key for herself, an attacker's way back in."""
    iam = ctx.dana.client("iam")
    keys = iam.list_access_keys(UserName=DANA)["AccessKeyMetadata"]
    if len(keys) >= 2:
        # IAM allows at most 2 keys per user; a leftover from an earlier run blocks this one
        print(f"   {DANA} already has 2 access keys (the IAM limit). Delete the extra one "
              f"(aws iam list-access-keys --user-name {DANA}), then rerun.")
        return "skipped"
    key = iam.create_access_key(UserName=DANA)["AccessKey"]
    ctx.created_key_ids.append(key["AccessKeyId"])
    # Never print the secret: the key is deleted in cleanup and nobody needs it
    print(f"   created extra access key {key['AccessKeyId']} (secret not shown, deleted in cleanup)")
    return "ok"


def create_backdoor_user(ctx, step):
    """2b: dana tries to create a backdoor user. Her policy denies it, which is the point."""
    try:
        ctx.dana.client("iam").create_user(UserName=BACKDOOR_USER)
    except ClientError as e:
        print(f"   denied creating {BACKDOOR_USER}: {e.response['Error']['Code']}")
        return "ok"
    # Should never happen: dana-policy.json has no iam:CreateUser
    print(f"   !! {BACKDOOR_USER} was CREATED, so dana's policy is too broad. Deleting it now.")
    ctx.admin.client("iam").delete_user(UserName=BACKDOOR_USER)
    return "ok"


def create_console_password(ctx, step):
    """2c: dana gives herself a console password, so the attacker can use the web console too."""
    password = secrets.token_urlsafe(16) + "Aa1!"  # meets the default password policy
    try:
        ctx.dana.client("iam").create_login_profile(
            UserName=DANA, Password=password, PasswordResetRequired=False)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"   {DANA} already has a console password from an earlier run. Remove it with "
                  f"'aws iam delete-login-profile --user-name {DANA}', then rerun.")
            return "skipped"
        raise
    ctx.created_login_profile = True
    ctx.dana_password = password
    print("   dana now has a console password (deleted in cleanup)")
    return "ok"


def console_login_wrong_password(ctx, step):
    """2d (manual): a failed console sign-in as dana."""
    if not ctx.dana_password:
        print("   dana has no console password (2c didn't run), skipping")
        return "skipped"
    print(f"   1. Open a private browser window: {console_url(ctx)}")
    print(f"   2. IAM user name: {DANA}   Password: anything WRONG")
    input("   Press Enter after the failed sign-in... ")
    return "ok"


def console_login_no_mfa(ctx, step):
    """2e (manual): a successful console sign-in as dana, without MFA."""
    if not ctx.dana_password:
        print("   dana has no console password (2c didn't run), skipping")
        return "skipped"
    print(f"   1. Same window: {console_url(ctx)}")
    print(f"   2. IAM user name: {DANA}   Password: {ctx.dana_password}")
    print("   3. Once signed in, sign out again (the password is deleted in cleanup)")
    input("   Press Enter after the successful sign-in... ")
    return "ok"


for step in STEPS:
    if step.id == "1a":
        step.run = probe_denied_secrets
    elif step.id == "1b":
        step.run = steal_demo_secret
    elif step.id == "3":
        step.run = detector_off
    elif step.id == "2a":
        step.run = create_backdoor_key
    elif step.id == "2b":
        step.run = create_backdoor_user
    elif step.id == "2c":
        step.run = create_console_password
    elif step.id == "2d":
        step.run = console_login_wrong_password
    elif step.id == "2e":
        step.run = console_login_no_mfa
    elif step.id == "4":
        step.run = mock_root

class Context:
    """Sessions and clients shared by every step, plus what cleanup must undo."""

    def __init__(self, dana_profile, admin_profile):
        self.dana = boto3.Session(profile_name=dana_profile, region_name=ACCOUNT_REGION)
        self.admin = boto3.Session(profile_name=admin_profile, region_name=ACCOUNT_REGION)
        self.logs = self.admin.client("logs")
        # Filled in by steps, emptied by cleanup()
        self.created_key_ids = []
        self.created_login_profile = False
        self.dana_password = None          # set by 2c, used by the manual sign-ins 2d/2e

# ARN stands form Amazon Resource Name
# Checks to make sure identity are who they say they are
def check_identities(ctx):
    dana_arn = ctx.dana.client("sts").get_caller_identity()["Arn"]
    admin_arn = ctx.admin.client("sts").get_caller_identity()["Arn"]
    print(f"dana profile  -> {dana_arn}")
    print(f"admin profile -> {admin_arn}")
    if not dana_arn.endswith(f":user/{DANA}"):
        sys.exit("The dana profile isn't dana-test. Fix it with 'aws configure --profile dana-test'.")
    if admin_arn.endswith(":root"):
        sys.exit("The admin profile is root. Use your own IAM user, never root.")

# Restarts dana profile to re-do the attack
def reset_dana(admin_profile):
    """Same as the 6B reset command, run with the admin profile (dana can't write DynamoDB)."""
    print("Resetting dana's baseline from fake_events.json ...")
    env = dict(os.environ)
    if admin_profile:
        env["AWS_PROFILE"] = admin_profile
        
    # Updated to use --from-file fake_events.json instead of --personas
    fake_events_path = os.path.join(REPO_ROOT, "fake_events.json")
    subprocess.run([sys.executable, os.path.join(REPO_ROOT, "helpers", "seed_baseline.py"),
                    "--from-file", fake_events_path, "--only", DANA], check=True, env=env)


def read_scores(ctx, step, since_ms):
    """Returns the detector's log lines for this step with built-in retry for propagation delay."""
    lines = []
    kwargs = {"logGroupName": LOG_GROUP, "startTime": since_ms, "filterPattern": '"score"'}
    
    # Retry up to 3 times to allow CloudTrail -> EventBridge -> Lambda propagation delay
    for attempt in range(3):
        lines = []
        paginator_kwargs = kwargs.copy()
        while True:
            page = ctx.logs.filter_log_events(**paginator_kwargs)
            for event in page.get("events", []):
                try:
                    line = json.loads(event["message"])
                except ValueError:
                    continue
                
                step_id = getattr(step, "identity", None) or ""
                if step_id in line.get("identity", "") and line.get("api") in step.apis:
                    lines.append(line)
            if "nextToken" not in page:
                break
            paginator_kwargs["nextToken"] = page["nextToken"]
            
        if lines:
            break
        time.sleep(5)
        
    return lines

def run_step(ctx, step, wait):
    print(f"\n== {step.id} {step.scenario}: {step.what}")
    if step.manual:
        print(f"   Manual step. Do this in a browser now: {step.what}")
    started_ms = int(time.time() * 1000) - 5000
    outcome = (step.run or attack_does_not_exist)(ctx, step)
    if outcome == "skipped":
        step.result = {"status": "SKIPPED"}
        return

    print(f"   waiting {wait}s for CloudTrail -> EventBridge -> Lambda ...")
    time.sleep(wait)
    lines = read_scores(ctx, step, started_ms)
    if not lines:
        step.result = {"status": "NO LOG", "score": None}
        return
    best = max(lines, key=lambda l: l.get("score", 0))
    passed = step.min_score is None or best.get("score", 0) >= step.min_score
    step.result = {"status": "PASS" if passed else "FAIL", "score": best.get("score"),
                   "alerted": best.get("alerted"), "reasons": best.get("reasons", [])}

def cleanup(ctx):
    """Always runs, even on Ctrl+C or a crash: leaves nothing behind."""
    print("\n== cleanup")
    iam = ctx.dana.client("iam")
    for key_id in ctx.created_key_ids:
        try:
            iam.delete_access_key(UserName=DANA, AccessKeyId=key_id)
            print(f"   deleted extra access key {key_id}")
        except ClientError as e:
            print(f"   !! could not delete access key {key_id}: {e}  -> delete it by hand")
    if ctx.created_login_profile:
        try:
            iam.delete_login_profile(UserName=DANA)
            print("   deleted dana's console password")
        except ClientError as e:
            print(f"   !! could not delete login profile: {e}  -> delete it by hand")

    # Safety net for detector-off: the forwarding rule must end ENABLED.
    events = ctx.dana.client("events", region_name=FWD_REGION)
    try:
        if events.describe_rule(Name=FWD_RULE)["State"] not in ENABLED_STATES:
            events.enable_rule(Name=FWD_RULE)
            print(f"   re-enabled {FWD_RULE} in {FWD_REGION}")
        restore_full_state(ctx)
        print(f"   {FWD_RULE} ({FWD_REGION}): {events.describe_rule(Name=FWD_RULE)['State']}")
    except ClientError as e:
        print(f"   !! could not check {FWD_RULE} in {FWD_REGION}: {e}  -> CHECK IT BY HAND NOW")


def print_table(steps):
    print("\n" + "=" * 100)
    print(f"{'Step':<5}{'Scenario':<14}{'Exercises':<17}{'Expected':<42}{'Score':>6}  Result")
    print("-" * 100)
    for s in steps:
        r = s.result or {"status": "NOT RUN"}
        score = "" if r.get("score") is None else r["score"]
        print(f"{s.id:<5}{s.scenario:<14}{s.exercises:<17}{s.expected[:40]:<42}{score!s:>6}  {r['status']}")
        for reason in r.get("reasons", []):
            print(f"{'':<36}- {reason}")
    print("=" * 100)
    print("Watchdog emails don't appear in the Lambda logs: check the inbox for step 3.")


# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", choices=SCENARIOS + ["all"])
    parser.add_argument("--dana-profile", default=DANA)
    parser.add_argument("--admin-profile", default=None, help="your own IAM user's profile (default: default profile)")
    parser.add_argument("--wait", type=int, default=20, help="seconds to wait before reading the logs for each step")
    parser.add_argument("--skip-reset", action="store_true", help="don't reset dana's baseline first")
    args = parser.parse_args()

    chosen = SCENARIOS if args.scenario == "all" else [args.scenario]
    steps = [s for s in STEPS if s.scenario in chosen]

    ctx = Context(args.dana_profile, args.admin_profile)
    check_identities(ctx)
    if not args.skip_reset:
        reset_dana(args.admin_profile)

    try:
        for step in steps:
            run_step(ctx, step, args.wait)
    finally:
        cleanup(ctx)
        print_table(steps)


if __name__ == "__main__":
    main()
