# Task 4: Any root activity should alert

Branch: `task-4-root-always-alerts`

This task only changes how the root user is scored.

Root currently gets a baseline like every other identity. A routine root call that matches that profile scores 0 and stays quiet. The project rule is that root should never be used, so any root event has to alert even when the API, region, hour, and IP all look normal.

## What changed

In `lambda/handler.py`, after the baseline checks and before the SNS decision:

```python
if ui.get("type") == "Root":
    score = max(score, ALERT_THRESHOLD)
    anomalies.append(
        "Activity performed by the AWS account root user, which should never be used."
    )
```

`userIdentity.type == "Root"` is the CloudTrail marker for the account root. `max` floors the score at 75. A routine root call that scored 0 becomes 75 and alerts. A root call that already scored more, such as `CreateAccessKey` at 80, keeps that higher score. The reason is always added, so the email says why it fired.

This also covers a root console login once Task 1 starts forwarding those events. The floor does not depend on the event name.

**Done when:** a root event that matches its profile still alerts. Test with a mocked event. Do not log in as root to test it.

Local mock result: a root `s3:CreateBucket` that matched the fake baseline on region, hour, IP, and API scored **75**, `alerted` true, reason `Activity performed by the AWS account root user, which should never be used.`

## AWS design practices and tools

This is still a detective control. The call is not blocked. Root can already do anything in the account, so a permission change cannot express "root should not be used." The detector is the control that makes that rule visible.

- **CloudTrail `userIdentity.type`.** Root is a distinct principal type, not an IAM user. The check is on that field, not on the ARN string.
- **Lambda scorer.** The floor sits after the baseline comparison, so normal-looking root activity is not excused by a profile.
- **Threshold 75.** Reuses `ALERT_THRESHOLD` instead of a second magic number. One alert path, one SNS topic.
- **Explainable alert.** The reason is plain language, not only a raised score. That is the same practice as the other signals.
- **Mock test, not a live root login.** Signing in as root to prove the rule would create the activity the rule exists to catch. The done check is a fake CloudTrail event.

## Challenges

**A baseline makes root look normal.** The first seed can record real root calls. After that, region, hour, IP, and API all match, and the score stays 0. The floor ignores the profile for this one principal type.

**Root is not an IAM user.** Assumed-role sessions resolve to the role ARN. Root must be matched on `type`, or a session that merely mentions root in another field is scored like everyone else.

**Do not test by logging in.** A real root login is the finding. The mock uses `userIdentity.type = "Root"` and a matching profile so the only reason it alerts is this rule.

