resource "aws_dynamodb_table" "products" {
  name         = "shop-products"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "sku"

  attribute {
    name = "sku"
    type = "S"
  }
}

resource "aws_dynamodb_table" "orders" {
  name         = "shop-orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "order_id"

  attribute {
    name = "order_id"
    type = "S"
  }
}

locals {
  products = {
    "SKU-1001" = { name = "Wireless Mouse", price = "24.99" }
    "SKU-1002" = { name = "Mechanical Keyboard", price = "89.00" }
    "SKU-1003" = { name = "USB-C Hub", price = "39.50" }
    "SKU-1004" = { name = "27in Monitor", price = "229.99" }
  }
}

resource "aws_dynamodb_table_item" "products" {
  for_each   = local.products
  table_name = aws_dynamodb_table.products.name
  hash_key   = aws_dynamodb_table.products.hash_key

  item = jsonencode({
    sku   = { S = each.key }
    name  = { S = each.value.name }
    price = { N = each.value.price }
  })
}
