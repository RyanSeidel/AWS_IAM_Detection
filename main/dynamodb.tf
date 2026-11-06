resource "aws_dynamodb_table" "baseline" {
  name           = "insider-threat-baseline"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5

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