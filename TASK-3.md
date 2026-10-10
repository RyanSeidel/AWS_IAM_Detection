# Task 3: Missing privilege-escalation APIs

Branch: `task-3-high-risk-apis`

This task only closes a gap in the high-risk list. It does not change console sign-in detection, detector tamper alerts, the root-user floor, or denied-call scoring.

The detector already scored a short list of IAM and data calls as high-risk (`AttachUserPolicy`, `CreateAccessKey`, secret reads, bucket exposure). Seven standard privilege-escalation and backdoor calls were missing. Those calls only scored if the identity had never used that API before (+20), which stays under the alert threshold of 75.

## What changed

These seven APIs go in `HIGH_RISK_APIS` in `lambda/handler.py` at **+40**, each mapped to a MITRE ATT&CK tactic:

| API | Tactic | Why it is here |
|---|---|---|
| `iam:CreateUser` | Persistence | New backdoor account. An unknown user has no baseline (+40), so this call scores 80 and alerts. |
| `iam:CreatePolicyVersion` | Privilege Escalation | A new policy version can grant admin without `AttachUserPolicy`. |
| `iam:SetDefaultPolicyVersion` | Privilege Escalation | Rolls the default version back to an older, broader document. |
| `iam:AddUserToGroup` | Privilege Escalation | Inherits whatever the group can already do. |
| `iam:UpdateAssumeRolePolicy` | Privilege Escalation | Rewrites a role trust policy so another principal can assume it. |
| `iam:DeactivateMFADevice` | Defense Evasion | Turns MFA off on an existing user. |
| `ec2:AuthorizeSecurityGroupIngress` | Defense Evasion | Opens a security group. Extra **+35** if the rule is `0.0.0.0/0` or `::/0`, which alerts on its own (40 + 35). |

EventBridge does not need a new filter. These are mutating calls (`readOnly = false`), so the existing rule already forwards them. IAM is global, so the IAM calls arrive in `us-east-1` no matter where the caller is.

**Done when:** an unknown user calling `iam:CreateUser` alerts (40 + 40 = 80), and the Scoring table in the main README lists these APIs.

## AWS design practices and tools

This is a detective control. It does not block the call. CloudTrail has already recorded it by the time we score it. Blocking would be a permission or an SCP. Task 3 is the second line: notice misuse of a credential that was allowed to make the call.

- **CloudTrail.** Account-wide management-event log. `CreateUser` and `AuthorizeSecurityGroupIngress` are management events, so they show up without data events.
- **EventBridge.** Filter at the edge. Keep mutating calls, drop service calls and CloudWatch Logs calls that would make the detector trigger itself. Task 3 rides the existing filter.
- **Lambda (`lambda/handler.py`).** The decision point. Resolve the identity, look up the baseline, add +40 if the API is on the list, publish only if the score is at least 75.
- **DynamoDB baseline.** Per-identity normal APIs, regions, hours, and IPs. The Lambda only reads it. The +40 from this task still needs a second signal (no baseline, new region, new IP, or the open-to-world bonus) before it alerts.
- **SNS.** The email states the score, the API, the reason, and the MITRE tactic. The finding explains itself.
- **Terraform.** The trail, rule, table, topic, and Lambda are already code. This task does not add a resource. It changes the scorer that Terraform deploys.
- **MITRE ATT&CK for Cloud.** Persistence, Privilege Escalation, and Defense Evasion are the labels on the alert, not just the raw event name.
- **Composite threshold.** One weak signal stays quiet. A scoped security-group change is only +40. Opening it to the world adds 35 and crosses 75 alone.
- **Fail closed.** If the baseline lookup errors, the event alerts instead of being dropped.

## Challenges

**The old list missed real escalation paths.** `AttachUserPolicy` was covered. `CreatePolicyVersion` and `SetDefaultPolicyVersion` were not, even though both change what a principal can do. `AddUserToGroup` and `UpdateAssumeRolePolicy` were the same gap. A stolen key could create a user or rewrite a trust policy and only pick up +20.

**A new user has no history.** `iam:CreateUser` is the backdoor case. The caller often has no profile either, so the create call scores 40 + 40. If we re-seed after a test, that create becomes "normal" and the signal dies.

**Not every security-group change is an attack.** A private CIDR is normal. Alerting on every rule would be noise. The extra +35 is only for `0.0.0.0/0` and `::/0`. CloudTrail nests those values under `requestParameters` (`ipPermissions` → `items` → `ipRanges` → `cidrIp`), so a single-field check misses them. The handler has to walk the whole parameter object.

**Baselines from the first seed were polluted.** The October 1 run learned read-only calls, including its own `LookupEvents` in every region. `admin.me` then looked normal in 17 regions, so a new-region signal could not fire for that user. The seed script now learns only events the detector scores.

**IPv6 and Lambda names caused false misses.** Home IPv6 addresses rotate, so the new-IP check now uses a `/64`. Lambda event names carry a version suffix (`CreateFunction20150331`). The handler strips those suffixes. Task 3's IAM and EC2 names do not have that suffix, but they use the same matcher.

**Teammate profiles are thin.** `rency.dev` and `shadab.dev` have one active hour each. `yael.dev` has no profile. Until there is more history, the hour signal fires often, and an unknown identity scores +40 on its own.

**The code can merge and still do nothing.** Phase 3 is not deployed. Task 3 does not change Terraform. The new weights run only after `terraform apply` ships the handler.
