# How to Change What We Detect

A practical guide for modifying the detection pipeline. Read this before
editing anything, so you change the right layer.

---

## The four layers

Detection behaviour is decided in four places. Changing the wrong one wastes
time or costs money.

| Layer | File | Controls | Change it when |
|---|---|---|---|
| 1. CloudTrail | `main/main.tf` | What AWS records at all | Almost never |
| 2. EventBridge | `main/eventbridge.tf` | What reaches the Lambda | You want a different set of API calls |
| 3. DynamoDB | seed data | What counts as "normal" | You want to tune false positives |
| 4. Lambda | `lambda/handler.py` | How it judges and explains | You're adding a signal or changing scoring |

**Rule of thumb:** if you want to detect a *different kind of activity*, change
layer 2. If you want to change *how suspicious* something looks, change layer
3 or 4.

---

## Layer 1 — CloudTrail (leave this alone)

CloudTrail already records every management event in the account. Our trail
has no event selectors, which means it captures all of them, and that is the
free tier.

**Do not add data events.** It's tempting — "let's detect S3 object reads" —
but data events bill at $0.10 per 100,000 with no free copy, and a single busy
bucket generates millions. This is the one change that could actually cost the
team money.

Filtering belongs in layer 2, where it's free.

---

## Layer 2 — EventBridge (the main knob)

This is where you decide which API calls wake the Lambda. Everything else
is silently dropped, at no cost.

Our current pattern, in `main/eventbridge.tf`:

```hcl
event_pattern = jsonencode({
  "detail-type" = ["AWS API Call via CloudTrail"]
  detail = {
    readOnly    = [false]
    eventSource = [{ "anything-but" = ["logs.amazonaws.com"] }]
    userIdentity = {
      invokedBy = [{ exists = false }]
      type      = ["IAMUser", "AssumedRole"]
    }
  }
})
```

Read it as: mutating calls only, not from CloudWatch Logs, not made by an AWS
service on its own behalf, by a human or an assumed role.

### Finding the event name you want

You need the exact `eventName` AWS uses. Three ways to find it:

**Just do the thing and look.** Most reliable.

```powershell
aws iam create-user --user-name throwaway-test
aws iam delete-user --user-name throwaway-test
aws logs tail /aws/lambda/insider-threat-detector --since 3m --filter-pattern "identity"
```

The `api` field in the output gives you `eventSource:eventName` exactly.

**CloudTrail Event history** in the console. Filter by event name, browse what
exists.

**Our own log bucket**, for anything that already happened:

```powershell
aws s3 ls s3://insider-threat-cloudtrail-021158484652/AWSLogs/ --recursive
```

### Pattern syntax you'll actually use

Exact match on a list (this is an OR):

```hcl
eventName = ["CreateUser", "DeleteUser", "AttachUserPolicy"]
```

Prefix match:

```hcl
eventName = [{ prefix = "Delete" }]
```

Exclusion:

```hcl
eventSource = [{ "anything-but" = ["logs.amazonaws.com"] }]
```

Field must be absent:

```hcl
invokedBy = [{ exists = false }]
```

Nested fields nest in the pattern:

```hcl
userIdentity = {
  sessionContext = {
    attributes = {
      mfaAuthenticated = ["false"]
    }
  }
}
```

Note that `mfaAuthenticated` is the **string** `"false"`, not a boolean.
CloudTrail is inconsistent about this — `readOnly` is a real boolean. If a
pattern silently matches nothing, a string/boolean mismatch is the usual
reason.

**Everything in a pattern is ANDed together.** Lists within a single field are
ORed. There is no way to express "A or B" across two different fields in one
rule — use two rules if you need that.

### Recipes

**Detect IAM changes** (privilege escalation, MITRE T1098):

```hcl
detail = {
  eventSource = ["iam.amazonaws.com"]
  eventName   = ["CreateUser", "CreateAccessKey", "AttachUserPolicy",
                 "AttachRolePolicy", "PutUserPolicy", "CreateLoginProfile"]
}
```

**Detect secrets access** (credential access, T1552):

```hcl
detail = {
  eventSource = ["secretsmanager.amazonaws.com", "ssm.amazonaws.com"]
  eventName   = ["GetSecretValue", "GetParameter", "GetParameters"]
}
```

Careful: these are read-only calls, so you'd have to drop the
`readOnly = [false]` line for them to match. That will increase volume.

**Detect anything destructive:**

```hcl
detail = {
  eventName = [{ prefix = "Delete" }]
}
```

**Detect logging being disabled** (defense evasion, T1562 — a classic
intrusion step):

```hcl
detail = {
  eventSource = ["cloudtrail.amazonaws.com"]
  eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
}
```

**Detect calls without MFA:**

```hcl
detail = {
  userIdentity = {
    sessionContext = {
      attributes = {
        mfaAuthenticated = ["false"]
      }
    }
  }
}
```

### Testing a pattern before deploying

The EventBridge console has a sandbox: **EventBridge -> Rules -> Create rule
-> Event pattern -> Test pattern**. Paste a real CloudTrail event body and
your pattern, and it tells you whether they match. Much faster than applying
and waiting.

Get a real event body by copying one from the Lambda logs, or from a file in
the trail bucket.

### The feedback loop — read this before adding a rule

Our Lambda writes to CloudWatch Logs. `CreateLogStream` is a mutating call. Our
first version matched it, which invoked the Lambda, which wrote a log, which
matched again.

The `anything-but: logs.amazonaws.com` clause is what stops it. **If you widen
the pattern, check you haven't reintroduced a loop.** Ask: does anything the
Lambda itself does now match this rule? A runaway loop is the only realistic
way this project costs real money.

After any pattern change, verify:

```powershell
aws logs tail /aws/lambda/insider-threat-detector --since 2m --filter-pattern "identity"
```

Every line should be activity you caused. If you see the detector's own role
`arn:aws:iam::021158484652:role/insider-threat-detector` in the identity
field, you have a loop — revert immediately.

---

## Layer 3 — the baseline (tuning false positives)

The DynamoDB table says what's normal per identity. Four facets:

| facet | meaning |
|---|---|
| `apis` | API calls this identity normally makes |
| `regions` | regions they normally work in |
| `hours` | UTC hours they're normally active |
| `source_ips` | IPs they normally connect from |

Change these when something legitimate keeps alerting. If Yael works late and
keeps tripping the off-hours signal, widen her `hours` facet rather than
weakening the rule for everyone.

### Adding or updating a facet

Write a JSON file and use `file://`. Inline JSON breaks under PowerShell, and
`Set-Content -Encoding UTF8` adds a BOM that breaks the parser.

```powershell
$enc = New-Object System.Text.UTF8Encoding($false)
$p = $PWD.Path

[IO.File]::WriteAllText("$p\item.json", '{"identity":{"S":"arn:aws:iam::021158484652:user/yael.dev"},"facet":{"S":"hours"},"values":{"SS":["13","14","15","16","17","18","19","20","21","22","23","00","01","02"]}}', $enc)

aws dynamodb put-item --table-name insider-threat-baseline --item file://item.json
Remove-Item item.json
```

`put-item` overwrites the whole item, so include every value you want to keep,
not just the new one.

### Reading what's in there

Everything:

```powershell
aws dynamodb scan --table-name insider-threat-baseline
```

One identity:

```powershell
$enc = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText("$PWD\k.json", '{":i":{"S":"arn:aws:iam::021158484652:user/admin.me"}}', $enc)
aws dynamodb query --table-name insider-threat-baseline --key-condition-expression "identity = :i" --expression-attribute-values file://k.json
Remove-Item k.json
```

### Adding a new facet type

Adding a fifth signal (say `user_agents`) needs no schema change — that's why
we used facet rows instead of one item per user. Just seed rows with the new
facet name and teach the Lambda to read them.

---

## Layer 4 — the Lambda (Phase 5 territory)

`lambda/handler.py`. Currently it alerts on everything and ignores the
baseline entirely. Phase 5 is where that changes.

### Deploying a code change

Terraform detects the change via `source_code_hash` and redeploys:

```powershell
cd main
terraform apply
```

No need to zip anything by hand — the `archive_file` data source does it.

### What Phase 5 needs to add

- Query DynamoDB for the identity's four facets
- Compare the event against each: unseen API, new region, off-hours, new IP,
  or no baseline at all
- Weight and sum into a composite score
- Only publish to SNS above a threshold
- Build a plain-language explanation naming which signals fired
- Attach a MITRE technique ID

Proposed weights: unseen API 3, new region 3, off-hours 2, new IP 2, unknown
identity 4. Threshold 5, so any two signals fire but one alone doesn't.

### Watch out for

`userIdentity.type` varies. `IAMUser` has `arn` directly. `AssumedRole` puts
the real principal at `sessionContext.sessionIssuer.arn`. `AWSService` records
have neither — always use `.get()` with defaults, never direct indexing.

`sourceIPAddress` isn't always an IP. Service calls put a hostname there.

`eventTime` is UTC, in ISO format. Parse the hour from it, don't assume local
time.

---

## How to read the output

Live tail:

```powershell
aws logs tail /aws/lambda/insider-threat-detector --follow
```

Just detections, recent:

```powershell
aws logs tail /aws/lambda/insider-threat-detector --since 5m --filter-pattern "identity"
```

Each line is one JSON object:

```json
{"identity": "arn:aws:iam::021158484652:user/admin.me",
 "identity_type": "IAMUser",
 "access_key": "AKIA...",
 "api": "s3.amazonaws.com:CreateBucket",
 "region": "us-east-1",
 "time": "2026-09-18T19:28:52Z",
 "source_ip": "35.147.145.30",
 "read_only": false}
```

`access_key` is worth noticing: it lets us baseline per *credential*, not just
per user. A stolen key behaving differently from its owner's normal pattern is
detectable even though the username matches.

Use `--since` tightly when checking a change. `--since 5m` often includes runs
from before your fix and makes it look like nothing happened.

---

## Testing any change

1. Make the change
2. `terraform apply` from `main/`
3. Trigger the activity you expect to match
4. `aws logs tail ... --since 2m --filter-pattern "identity"`
5. Confirm it fired, and confirm nothing unexpected did

Safe throwaway triggers:

```powershell
# S3
aws s3api create-bucket --bucket test-detect-021158484652
aws s3api delete-bucket --bucket test-detect-021158484652

# IAM
aws iam create-user --user-name throwaway-test
aws iam delete-user --user-name throwaway-test

# Tags
aws s3api put-bucket-tagging --bucket insider-threat-cloudtrail-021158484652 --tagging "TagSet=[{Key=test,Value=1}]"
```

---

## When a rule doesn't fire

Work down the chain, in this order.

**Is CloudTrail recording it?** Check the trail bucket or CloudTrail Event
history in the console. If it's not there, it isn't a management event and
EventBridge will never see it.

**Does the pattern match?** Use the EventBridge console sandbox with a real
event body. This catches most problems, usually a string-vs-boolean mismatch
or a misspelled `eventName`.

**Is the rule enabled and targeted?**

```powershell
aws events list-targets-by-rule --rule insider-threat-risky-calls
```

**Did the Lambda error?** Look for tracebacks:

```powershell
aws logs tail /aws/lambda/insider-threat-detector --since 10m
```

`AccessDenied` here means the IAM role is missing a permission. Add it to
`aws_iam_role_policy.detector` in `main/eventbridge.tf` — the permissions
policy, not `aws_iam_role`, which is the trust policy.

**Timing.** CloudTrail to EventBridge takes a few seconds, normally under ten,
occasionally a minute or two. Don't conclude failure after thirty seconds.

---

## Things that would cost money

- CloudTrail data events or Insights
- A second trail in the same region
- `aws:kms` instead of `AES256` on a bucket
- Putting the Lambda in a VPC (implies a NAT Gateway, ~$33/month)
- A CloudWatch log group without `retention_in_days`
- GuardDuty, Config, Security Hub, Macie
- An EventBridge pattern that lets the Lambda retrigger itself

Check spend after any significant change:

```powershell
aws ce get-cost-and-usage --time-period Start=2026-09-01,End=2026-09-30 --granularity MONTHLY --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE
```
