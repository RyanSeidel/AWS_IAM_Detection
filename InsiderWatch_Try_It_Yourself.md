# InsiderWatch: Try It in Your Own AWS Account

AWS IAM Insider Threat Detection, Group 01. Takes about 15 minutes, runs in the browser, nothing to install.

## You need

- An AWS account and a login that can create IAM users and roles (root or an admin user). A real AWS account is required - AWS Builder ID is not sufficient
- An email address for alerts.

## Steps

1. **Sign in** at console.aws.amazon.com.
2. **Pick the region:** top right, choose **US East (N. Virginia) us-east-1**.
3. **Open CloudShell:** click the **>_** icon in the top bar and wait for the terminal.
4. **Deploy** (replace the email; takes about 8 to 10 minutes):

```bash
git clone https://github.com/RyanSeidel/AWS_IAM_Detection.git
```

**Why:** *Downloads our code (Terraform, Lambda, dashboard and scripts) into CloudShell.*

```bash
cd AWS_IAM_Detection
```

**Why:** *Moves into the project folder so the next command can find the script.*

```bash
bash demo/quickstart.sh you@example.com
```

**Why:** *Installs Terraform, deploys the whole system into your account (CloudTrail, EventBridge, detector Lambda, tables, email alerts, dashboard), creates dana-test as the insider with her own key, and prints the dashboard link and login. Your email receives the alerts.*

5. **Log in:** open the Dashboard link the script prints. Username **admin@insider.com**, password as printed. Set a new password when asked.

```
username = "admin@insider.com"
temporary_password = "SecretPassword123!"
```

6. **Attack** as the insider dana-test, in CloudShell (real AWS calls with her real key; she has no history yet, so each call starts at +40 as an unknown identity):

```bash
aws ssm get-parameter --name /demo/db-password --with-decryption --region eu-west-1 --profile dana-test
```

**Why:** *Dana reads a stored database password: stealing a secret (Credential Access). Scores 80 (40 unknown identity + 40 high-risk call).*

```bash
aws iam create-access-key --user-name dana-test --profile dana-test
```

**Why:** *Dana makes an extra key so she keeps access later: a backdoor (Persistence). Scores 80.*

```bash
aws iam create-user --user-name backdoor-admin --profile dana-test
```

**Why:** *Dana tries to create a new user she isn't allowed to. It fails with AccessDenied, which is expected, and the failed attempt still alerts. Scores 105.*

7. **See the alerts:** after 1 to 5 minutes, choose **dana-test** in the dashboard sidebar and open **My alerts**.

**Why:** *Shows each attack with its score, the MITRE ATT&CK tactic and the reasons it was flagged.*

8. **Block the insider (prevention):** on **My alerts**, click **Block this identity**, then **Yes, Block**.

**Why:** *Detection alone only tells you. Block stops her: it attaches a deny-all policy to dana-test and disables her access keys, and emails you that it was done.*

Then try her attack again in CloudShell:

```bash
aws ssm get-parameter --name /demo/db-password --with-decryption --region eu-west-1 --profile dana-test
```

**Why:** *Proves the block works: the same call that succeeded before now fails, because her key no longer works.*

9. **Unblock (do this before cleanup if you blocked her):** click **Revoke / Unblock**, then **Yes, Revoke**.

**Why:** *Undoes the block (removes the deny-all policy and turns her keys back on), for when an alert turns out to be a false alarm.*

10. **Clean up** so nothing keeps running or costing money:

```bash
bash demo/cleanup.sh you@example.com
```

**Why:** *Deletes everything the quickstart created, including dana-test, so nothing is left running in your account.*

## Good to know

- Signed in as root? A few root alerts appear during setup. Root activity always alerts, by design.
- For alert emails, click Confirm subscription in the email from AWS Notifications.
- Blocking is a manual click, not automatic, so a person decides. The root user and the detector itself can never be blocked.
- Cost: small, but not always free. The dashboard runs on a t3.micro server. On AWS accounts created on or after July 15, 2025, this is covered by the free plan credits. On older accounts it is free only if t3.micro is free-tier eligible there (check the EC2 console); otherwise it costs about $0.25 per day while running. Run the cleanup step when done so nothing keeps running.
- More detail: github.com/RyanSeidel/AWS_IAM_Detection (README).

## Observability Note: Account Type Issues Observed During Demo

Some users encountered deployment or permission failures because they were signed in with an AWS Builder ID rather than a real AWS account. An AWS Builder ID is a profile used for AWS learning and developer sites (Skill Builder, Builder Center, Amazon Q, etc.) and is not an AWS account login. When a console or sandbox is launched from one of those sites, AWS provisions a temporary practice account that belongs to an AWS-managed organization (for example, a member of organization 126267012055). Users are authenticated through a restricted role such as AccountFullAccessRole rather than as root, and organization service control policies deliberately limit certain services (particularly parts of EC2) to keep the practice environment low-cost and safe. To run the demo successfully, participants must create a genuine AWS account at aws.amazon.com and sign in at console.aws.amazon.com as the Root user with that account’s email address.
