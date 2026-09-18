# CLAUDE.md

Context for AI coding agents working in this repo. Read before making changes.

## What this is

A university course project: near-real-time insider threat and credential
compromise detection on AWS, deployed entirely as Terraform.

    CloudTrail -> EventBridge -> Lambda -> DynamoDB baseline -> SNS email alert

The premise is that a hijacked account and a malicious insider look identical
in logs, so we detect on *unusual-for-this-identity* behaviour rather than
known-bad signatures. Every alert must explain in plain language why it fired.

Team of four. Graded on a live pitch plus Canvas submission.

## Hard constraints — do not violate

This runs in a student AWS account with a near-zero budget. These rules are
not stylistic; breaking them costs real money.

- **Never create a `aws_kms_key` or `aws_kms_replica_key`.** A customer managed
  key is $1/month each. Use `sse_algorithm = "AES256"` (SSE-S3) for buckets and
  the default AWS-owned key for DynamoDB.
- **Never enable CloudTrail data events, network activity events, or Insights.**
  Management events only. Data events bill at $0.10/100k with no free copy and
  are the single most common cause of surprise CloudTrail bills.
- **Never create a second CloudTrail trail.** Only the first copy of management
  events per region is free. A duplicate trail is billed.
- **Never put the Lambda in a VPC.** That implies a NAT Gateway at ~$33/month.
  The Lambda only calls DynamoDB and SNS, which are public AWS endpoints.
- **Always set `retention_in_days` on every `aws_cloudwatch_log_group`.**
  The default is never-expire.
- **Never enable GuardDuty, Security Hub, Config, or Macie.** All bill per
  event or per resource. GuardDuty in particular is the tool this project is
  positioned against, not one we deploy.
- **DynamoDB stays in `PROVISIONED` mode at 1 RCU / 1 WCU.** Well inside the
  25/25 always-free allowance.
- Single region, `us-east-1`. Multi-region is an explicit non-goal.

If a task seems to require breaking one of these, stop and say so rather than
working around it.

## Workflow rules

- **Run `terraform plan`, never `terraform apply`.** Applies are done by a
  human. Show the plan and stop.
- Run `terraform fmt` and `terraform validate` before declaring work finished.
- Never commit `*.tfstate`, `*.tfvars`, `backend.hcl`, or anything containing
  the AWS account ID. Check `.gitignore` before adding files.
- Do not `git push` or open PRs unless explicitly asked.
- Work one phase at a time. Do not scaffold future phases speculatively.

## Layout

    bootstrap/   Run once, local state. Creates the S3 state bucket.
                 Do not modify unless explicitly asked.
    main/        Everything else. Remote state, one file per concern:
                 versions.tf, providers.tf, variables.tf, outputs.tf,
                 cloudtrail.tf, and one .tf per phase going forward.
    lambda/      Python source for the detection function (Phase 5).

## Conventions

- Terraform >= 1.10, AWS provider ~> 6.0.
- Resource names use `local.<thing>_name` built from `var.project_name` and,
  where global uniqueness is needed, the account ID from
  `data.aws_caller_identity.current`.
- Tags come from `default_tags` in the provider block. Do not tag resources
  individually.
- Every resource gets a comment explaining *why*, especially where a cheaper
  or safer option was deliberately chosen.
- Python: standard library plus boto3 only. No external dependencies, so the
  Lambda can be packaged with `archive_file` and needs no layers.
- IAM policies are least-privilege and resource-scoped. No `"Resource": "*"`
  except where the API genuinely requires it, and comment when it does.

## Current status

Nothing is deployed to AWS yet. Phase 1 and 2 code exists in the repo but has
never been applied, so no resources exist and there is no remote state. Do not
assume any resource, bucket, or trail is live.

- [~] Phase 1 — Terraform backend bootstrap (written, not applied)
- [~] Phase 2 — CloudTrail + log bucket (written, not applied)
- [ ] Phase 3 — DynamoDB baseline table
- [ ] Phase 4 — EventBridge rule + stub Lambda
- [ ] Phase 5 — Detection Lambda with composite scoring
- [ ] Phase 6 — SNS alerting with plain-language explanations
- [ ] Phase 7 — Attack simulation runbook, README, teardown

Update this checklist when a phase is finished and verified.

## Design decisions already made

- The CloudTrail bucket policy builds the trail ARN by hand in `locals`
  rather than referencing `aws_cloudtrail.main.arn`. CloudTrail validates the
  bucket policy at creation time, so referencing the trail is a dependency
  cycle. Do not "fix" this.
- `backend "s3" {}` is intentionally empty. Values come from `backend.hcl`
  via `-backend-config` so the account ID is never committed.
- State locking uses `use_lockfile = true` (S3 native, Terraform 1.10+).
  Do not add a DynamoDB lock table.
- `force_destroy = true` on the CloudTrail bucket only, so `terraform destroy`
  works between work sessions. Not appropriate for production, and the comment
  in the code says so.
- Filtering of noisy events happens in the EventBridge rule, not in the trail.
  Narrowing the trail would save nothing and would cost us baseline data.
