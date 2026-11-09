#!/usr/bin/env bash
# One-command deploy of the whole project into YOUR OWN AWS account, from AWS CloudShell.
#
#   git clone -b test https://github.com/RyanSeidel/AWS_IAM_Detection.git
#   cd AWS_IAM_Detection
#   bash demo/quickstart.sh you@example.com
#
# It installs Terraform, keeps Terraform state in this folder (not the team's
# S3 bucket), deploys the detector + dashboard + the dana-test demo user, gives
# dana a key, and waits until the dashboard is up. Takes about 8-10 minutes.
# Remove everything afterwards with: bash demo/cleanup.sh you@example.com
set -euo pipefail

EMAIL="${1:-}"
if [[ -z "$EMAIL" ]]; then
  echo "Usage: bash demo/quickstart.sh you@example.com"
  exit 1
fi

TEAM_ACCOUNT="021158484652"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
export TF_DATA_DIR=/tmp/tfdata            # CloudShell's home folder is only 1 GB
export PATH="$HOME/bin:$PATH"

step() { echo; echo "==> $*"; }

step "1/7 Checking your AWS login"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
echo "Account: $ACCOUNT"
if [[ "$ACCOUNT" == "$TEAM_ACCOUNT" ]]; then
  echo "This is the team's account. Use the normal setup in the README instead,"
  echo "so you share the team's Terraform state."
  exit 1
fi

step "2/7 Installing Terraform and boto3 (if missing)"
if ! command -v terraform >/dev/null; then
  mkdir -p "$HOME/bin"
  TFV=$(curl -fsS https://checkpoint-api.hashicorp.com/v1/check/terraform \
        | python3 -c 'import sys, json; print(json.load(sys.stdin)["current_version"])')
  curl -fsSLo /tmp/terraform.zip "https://releases.hashicorp.com/terraform/${TFV}/terraform_${TFV}_linux_amd64.zip"
  unzip -oq /tmp/terraform.zip -d "$HOME/bin"
fi
terraform -version | head -1
python3 -c 'import boto3' 2>/dev/null || pip3 install --user -q boto3

step "3/7 Using local Terraform state, and pointing dana's fake history at your account"
# fake_events.json was generated in the team's account, so its ARNs carry the
# team's account ID. Without this, dana's baseline would be saved under an ARN
# that doesn't exist here, and the detector would treat her as "unknown".
sed -i "s/${TEAM_ACCOUNT}/${ACCOUNT}/g" "$ROOT/fake_events.json"

cd "$ROOT/main"
printf 'terraform {\n  backend "local" {}\n}\n' > backend_override.tf
terraform init -input=false -reconfigure >/dev/null
echo "OK"

step "4/7 Deploying (about 3-4 minutes)"
terraform apply -input=false -auto-approve -var="alert_email=$EMAIL" -var="demo_user=true"

step "5/7 Giving dana-test an access key (the 'stolen' key the attacker uses)"
# Remove old keys first: IAM allows only 2 per user.
for k in $(aws iam list-access-keys --user-name dana-test --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name dana-test --access-key-id "$k"
done
read -r AK SK < <(aws iam create-access-key --user-name dana-test \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
aws configure set aws_access_key_id "$AK" --profile dana-test
aws configure set aws_secret_access_key "$SK" --profile dana-test
aws configure set region us-east-1 --profile dana-test
echo "Saved as AWS profile 'dana-test'"

step "6/7 Waiting for the dashboard to start (about 3-5 minutes)"
URL=$(terraform output -raw dashboard_url)
UP=no
for _ in $(seq 1 40); do
  if [[ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$URL")" == "200" ]]; then
    UP=yes
    break
  fi
  sleep 10
done
if [[ "$UP" == "yes" ]]; then
  echo "Dashboard is up"
else
  echo "Not answering yet; give it a few more minutes and refresh the link below."
fi

TEMP_PW=$(grep -oP 'temporary_password\s*=\s*"\K[^"]+' cognito.tf)

step "7/7 Done"
cat <<MSG

  Dashboard:  $URL
  Username:   admin@insider.com
  Password:   $TEMP_PW  (temporary; you'll be asked to set your own)

  Check your email ($EMAIL) and click the SNS confirmation link to get alert emails.

  Launch an attack, then open "My alerts" (alerts appear within about 1-5 minutes):
    cd $ROOT
    python3 helpers/simulate_attack.py secret-theft

  When finished, remove everything (stops all costs):
    bash demo/cleanup.sh $EMAIL
MSG
