resource "aws_dynamodb_table" "baseline" {
  name           = "insider-threat-baseline"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1

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
