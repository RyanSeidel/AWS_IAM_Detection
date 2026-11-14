#!/usr/bin/env bash
# Removes everything demo/quickstart.sh created in your AWS account.
#   bash demo/cleanup.sh you@example.com
set -euo pipefail

EMAIL="${1:-}"
if [[ -z "$EMAIL" ]]; then
  echo "Usage: bash demo/cleanup.sh you@example.com"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
export TF_DATA_DIR=/tmp/tfdata
export PATH="$HOME/bin:$PATH"

cd "$ROOT/main"
if [[ ! -f backend_override.tf ]]; then
  echo "No backend_override.tf here: this folder wasn't set up by demo/quickstart.sh."
  echo "Refusing to run, so the team's shared stack is never destroyed by accident."
  exit 1
fi

# CloudShell may have restarted and cleared /tmp, so init again (quick).
terraform init -input=false -reconfigure >/dev/null
terraform destroy -input=false -auto-approve -var="alert_email=$EMAIL" -var="demo_user=true"

# Forget dana's deleted key.
python3 - <<'PY'
import configparser, os
for name, section in (("credentials", "dana-test"), ("config", "profile dana-test")):
    path = os.path.expanduser(f"~/.aws/{name}")
    cp = configparser.RawConfigParser()
    cp.read(path)
    if cp.remove_section(section):
        with open(path, "w") as f:
            cp.write(f)
PY

echo
echo "All removed. You can close CloudShell."
