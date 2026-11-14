# Task 7A: dana-test, the fake employee whose "stolen" key the attack simulator uses.
# Off by default; create her with:  terraform apply -var="demo_user=true"
#
# Her access key is made by hand (aws iam create-access-key), never here, so no
# real secret ends up in Terraform state. Don't add an aws_iam_access_key.

variable "demo_user" {
  type    = bool
  default = false
}

resource "aws_iam_user" "dana" {
  count = var.demo_user ? 1 : 0
  name  = "dana-test"

  # Lets demo_user=false remove her even if the hand-made access key or the
  # console password from the persistence scenario were left behind.
  force_destroy = true
}

resource "aws_iam_user_policy" "dana" {
  count = var.demo_user ? 1 : 0
  name  = "dana-demo"
  user  = aws_iam_user.dana[0].name
  policy = templatefile("${path.module}/../dana-policy.json", {
    account_id = data.aws_caller_identity.current.account_id
    # Only the eu-west-1 forwarding rule, never the us-east-1 main rule:
    # if that were left disabled the whole detector would be off.
    fwd_rule = aws_cloudwatch_event_rule.forward["eu-west-1"].name
  })
}

# Fake secret for the secret-theft scenario. It lives in eu-west-1, so reading
# it also trips the new-region signal.
resource "aws_ssm_parameter" "db_password" {
  count  = var.demo_user ? 1 : 0
  region = "eu-west-1"
  name   = "/demo/db-password"
  type   = "SecureString"
  value  = "fake-not-real"
}
