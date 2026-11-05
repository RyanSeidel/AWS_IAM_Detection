# Phase 6 (revised): Security Console for InsiderWatch

This replaces the plan in `Dashboard-Plan.pdf`. Tasks 8 and 9 are unchanged.
Everything after them is simpler, and nobody needs a new login.

## Why the plan changed

The original Phase 6 builds a hosted student website: a Cognito login, API
Gateway, a dashboard Lambda, and CloudFront + S3. That fits a classroom where
students watch their own activity.

But InsiderWatch is meant to be a **product any company deploys into its own
AWS account**. The people who use it are that company's security and cloud
admins, and they already sign in to the AWS console and CLI. A second website
with a second login would add cost, add something new to attack, and add four
tasks, without giving those admins anything they don't already have.

**New goal:** one `terraform apply` gives a company detection, email alerts,
alert history, and a security console inside the AWS console. No new logins,
and $0/month at small scale.

## Principles

1. **No new logins.** Admins use the AWS console and CLI they already have.
2. **Alerts live where security teams already work.** That's the AWS console today, and Security Hub later.
3. **Anyone can deploy it.** Nothing hard-coded to our account.
4. **One scoring engine.** The detector, the CLI and the what-if calculator all use `scoring.py`.
5. **Only admins see results.** Employees are the people being monitored. Showing them their own baseline would teach them how to stay under the threshold.

## Architecture

```
Company's AWS account (one terraform apply, run by its admin)

CloudTrail ─► EventBridge ─► detector Lambda (scoring.py) ─┬─► SNS email
                                                           ├─► alerts table (DynamoDB, 30-day TTL)
                                                           └─► structured log line (CloudWatch Logs)
                                                                      │
Admin ─► AWS console ─► CloudWatch dashboard "InsiderWatch" ◄─────────┘
Admin ─► AWS CLI     ─► helpers/insiderwatch.py (baseline, alerts, what-if)
```

The dashboard reads data from AWS, never from anyone's Terraform. Terraform
runs once to build everything. After that:

1. Employees do their normal work in AWS.
2. CloudTrail records it.
3. The detector scores it.
4. The dashboard and CLI show the results.

## Who can see the dashboard

We don't write any access-check code. **AWS IAM decides**, using the
permissions on each person's IAM user or role.

| To use | Permissions needed |
|---|---|
| CloudWatch dashboard | `cloudwatch:GetDashboard`, `cloudwatch:ListDashboards` |
| Its log widgets | `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`, `logs:DescribeLogGroups` on `/aws/lambda/insider-threat-detector` |
| Admin CLI | `dynamodb:GetItem`, `Query`, `Scan` on the baseline and alerts tables |

Terraform creates a read-only **`insider-threat-analyst`** policy with exactly
these permissions, and the company attaches it to its security team. Admins
(for example, anyone with `AdministratorAccess`) can already see everything.
AWS refuses everyone else with AccessDenied before our code even runs.

Give the security team the analyst policy rather than admin rights. In an
insider-threat tool, the people watching the alerts shouldn't also be able to
switch off the detector.

**Why not a Cognito login?** A custom website can't read anyone's AWS CLI
credentials, so it would need its own accounts and passwords. The company's
admins already sign in to the AWS console, a hosted website that already
knows who they are. A second login would only add passwords to manage and one
more thing to attack.

## Tasks

| # | Task | Branch | Depends on | Cost | Owner |
|---|---|---|---|---|---|
| 8 | Move scoring into `lambda/scoring.py` (+ `explain_baseline`, `what_if`) | task-8-scoring-module | none | $0 | |
| 9 | Alerts table; detector saves every scored event (email kept) | task-9-alerts-table | 8 | $0 | |
| 10 | Portable deploy: no hard-coded account, `-backend-config` for state | task-10-portable-deploy | none | $0 | |
| 11 | CloudWatch "InsiderWatch" dashboard in Terraform | task-11-console-dashboard | none (better after 9) | $0 | |
| 12 | Admin CLI `helpers/insiderwatch.py` + analyst policy | task-12-admin-cli | 8, 9 | $0 | |
| 13 | `enable_vpc` switch (optional hardening) | task-13-vpc-toggle | 9 | $0 off / ~$7.30 on | |
| 14 | Deployment + operator guides | task-14-guides | 10, 11, 12 | $0 | |
| 15 | Security Hub findings (stretch) | task-15-security-hub | 9 | ~$0 at low volume | |

Tasks 8, 10 and 11 can start in parallel. Put your name in the Owner column
when you pick one up.

### 8 · Shared scoring module (unchanged)
- Create `lambda/scoring.py` and move into it:
  - the weights and `HIGH_RISK_APIS`
  - the helpers `ip_key`, `is_denied` and `resolve_identity`
  - `score_event(detail, baseline)`

  Only move the code. Don't change any logic.
- Add `explain_baseline(profile)` and `what_if(profile, api, region, hour, ip, denied)`.
- In `main/eventbridge.tf`, change the archive to `source_dir = "../lambda"` instead of `source_file`.
- **Done when:** `tests/test_handler.py` passes unchanged, the new `tests/test_scoring.py` passes, and `what_if(rency, "iam:CreateUser", "eu-west-1", …)` returns 135.

### 9 · Alerts table (unchanged)
- Create `insider-threat-alerts`: on-demand billing, partition key `identity`, sort key `eventTime#eventID`, TTL of 30 days, and a GSI `by-alerted`.
- The detector calls `put_item` for every scored event, including the email subject and body. If a write fails, log it, and still send the email.
- **Done when:** `simulate_attack.py secret-theft` sends the email and writes matching rows.

### 10 · Portable deploy (new)
- Remove `bucket = "insider-threat-tfstate-021158484652"` from [main/main.tf](../main/main.tf). Pass the bucket when initializing instead:
  ```powershell
  terraform init -backend-config="bucket=insider-threat-tfstate-<account-id>"
  ```
  [bootstrap/main.tf](../bootstrap/main.tf) already names the bucket after the account.
- Grep the code and docs for `021158484652`. Replace each copy with `data.aws_caller_identity` or a placeholder.
- **Done when:** a teammate deploys bootstrap + main into a fresh account without editing any `.tf` file.

### 11 · CloudWatch "InsiderWatch" dashboard (replaces Cognito, API and frontend)
- In `main/dashboard.tf`, add an `aws_cloudwatch_dashboard` with Logs Insights widgets over `/aws/lambda/insider-threat-detector`. The detector already logs one JSON line per scored event ([lambda/handler.py](../lambda/handler.py), at the end of `handler`).
- Widgets:
  - alert count (score ≥ 75)
  - recent alerts table (time, identity, API, region, IP, score, top reason)
  - alerts by identity
  - alerts by MITRE tactic
  - score over time
  - tamper events
- Example query:
  ```
  fields @timestamp, identity, api, region, source_ip, score, reasons.0
  | filter score >= 75
  | sort @timestamp desc
  ```
- Raise the log group's retention from 7 to 30 days, to match the alerts table.
- Output the dashboard's console URL.
- **Done when:** after `secret-theft`, the alert appears on the dashboard within about 2 minutes, and nobody had to sign in to anything new.

### 12 · Admin CLI (replaces the CLI baseline task and the attack runner)
- `helpers/insiderwatch.py` uses the admin's own AWS CLI credentials:
  - `baseline <identity>`: what's normal, and how many points each new value would add
  - `alerts [--identity X] [--since 7d]`: reads the alerts table
  - `what-if <identity> <api> --region … --hour … --ip …`: calls `scoring.what_if`
- Create the `insider-threat-analyst` IAM policy described above.
- **Done when:** `what-if rency.dev iam:CreateUser --region eu-west-1` prints 135, and a user without the analyst policy gets AccessDenied.

### 13 · `enable_vpc` (optional)
- Defaults to `false`, which leaves the stack exactly as it is today.
- With `true`, the detector runs in private subnets. It reaches DynamoDB through a free gateway endpoint and SNS through an interface endpoint (~$7.30/month).
- **Done when:** with `false`, `terraform plan` shows no changes. With `true`, an attack still sends an email and saves an alert.

### 14 · Guides
- `docs/DEPLOY.md`: prerequisites → bootstrap → main → confirm email → seed baselines → first alert.
- `docs/OPERATOR_GUIDE.md`: reading an alert, using the dashboard and CLI, granting the analyst policy, and tearing down.
- **Done when:** a classmate deploys it into their own account and sees their first alert using only the guides.

### 15 · Security Hub findings (stretch)
- Send each alert to Security Hub as a finding, so it appears alongside the company's other AWS security findings.

## Dropped from the original plan

| Original task | Why it's dropped |
|---|---|
| 11 Cognito login | Admins already have AWS logins. A second password adds risk and nothing else. |
| 12 Dashboard API | The console and CLI read AWS directly, so no custom API is needed. |
| 13 S3 + CloudFront frontend | Replaced by the CloudWatch dashboard. |
| 15 Attacks from the UI | `simulate_attack.py` already runs them for demos and testing. |
| Employee self-view | It shows people exactly how to stay under the threshold. |

## Known product gap (Phase 7)

Most companies sign in through IAM Identity Center (SSO). CloudTrail records
those people as `AssumedRole` sessions, and `resolve_identity` currently keys
them on the role's ARN. Everyone who shares a permission set would therefore
share **one** baseline. Phase 7 should key on the role plus the session name,
which is the person's username or email.

## Cost

| Item | Monthly cost |
|---|---|
| Lambda, DynamoDB on-demand, SNS email | ~$0 (free tier) |
| CloudWatch dashboard | $0 (3 dashboards free) |
| Logs Insights queries | fractions of a cent |
| `enable_vpc = true` (SNS interface endpoint) | ~$7.30 + $0.01/GB |

Turn the VPC off, or run `terraform destroy`, when you don't need it.

## 5-minute demo

Get ready before you start: the dashboard is open, dana's baseline is seeded,
and the forwarding rule is `ENABLED`.

| Time | What to show |
|---|---|
| 0:00–0:45 | The problem: a stolen key looks like a normal user. Show the architecture. |
| 0:45–1:30 | The InsiderWatch dashboard and `insiderwatch.py baseline dana-test` |
| 1:30–2:00 | Run `simulate_attack.py secret-theft` live |
| 2:00–3:00 | While waiting: `insiderwatch.py what-if dana-test iam:CreateUser --region eu-west-1` → 135 |
| 3:00–4:15 | The alert arrives: the email, then the dashboard row and its reasons |
| 4:15–5:00 | Tamper detection: the watchdog email from an earlier `detector-off` run. Then questions. |

**Backup:** run the attack once earlier that day. CloudTrail sometimes takes a
few minutes to deliver events, and the earlier alert is there to show if this
one is late.

## How we'll know Phase 6 is done

- `python -m unittest -v tests/test_handler.py tests/test_scoring.py tests/test_simulate_attack.py` passes.
- A teammate deploys into a fresh account using only `docs/DEPLOY.md`.
- One `secret-theft` run shows the same score (160) in the email, the alerts table, the dashboard and the CLI.
