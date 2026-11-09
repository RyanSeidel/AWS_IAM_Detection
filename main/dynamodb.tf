# Data protection for the detector's tables (off by default, like the
# ALB/ASG option, so nobody reusing this project pays for it unknowingly).
# When true:
#   - deletion protection: DeleteTable fails until protection is turned off
#     again (that UpdateTable call is itself flagged as tampering), and
#   - point-in-time recovery: continuous backups for 35 days, so either table
#     can be restored to any second after a malicious delete.
# Teardown with it on: apply with protect_data=false first, then destroy.
variable "protect_data" {
  description = "Turn on deletion protection and point-in-time recovery for the DynamoDB tables"
  type        = bool
  default     = false
}

resource "aws_dynamodb_table" "baseline" {
  name           = "insider-threat-baseline"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5

  deletion_protection_enabled = var.protect_data

  point_in_time_recovery {
    enabled = var.protect_data
  }

  hash_key  = "identity"
  range_key = "facet"

  attribute {
    name = "identity"
    type = "S"
  }

  attribute {
    name = "facet"
    type = "S"
  }
}

output "baseline_table" {
  value = aws_dynamodb_table.baseline.name
}

resource "aws_dynamodb_table" "alerts" {
  name           = "insider-threat-alerts"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "identity"
  range_key      = "sk"

  deletion_protection_enabled = var.protect_data

  point_in_time_recovery {
    enabled = var.protect_data
  }

  attribute {
    name = "identity"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  attribute {
    name = "alerted"
    type = "S"
  }

  global_secondary_index {
    name            = "by-alerted"
    hash_key        = "alerted"
    range_key       = "sk"
    projection_type = "ALL"
    # GSI requires its own provisioned limits when the table is set to PROVISIONED
    read_capacity   = 5
    write_capacity  = 5
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

output "alerts_table" {
  value = aws_dynamodb_table.alerts.name
}