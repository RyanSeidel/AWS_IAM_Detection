# 1. COGNITO USER POOL
resource "aws_cognito_user_pool" "pool" {
  name = "insider-dashboard-pool"
  
  admin_create_user_config {
    allow_admin_create_user_only = true 
  }
}

# 2. APP CLIENT (Configured for Python API access)
resource "aws_cognito_user_pool_client" "client" {
  name            = "streamlit-boto3-client"
  user_pool_id    = aws_cognito_user_pool.pool.id
  generate_secret = false 
  
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH", 
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]
}

# 3. DEFAULT ADMIN USER
resource "aws_cognito_user" "admin" {
  user_pool_id       = aws_cognito_user_pool.pool.id
  username           = "admin@insider.com" 
  temporary_password = "SecretPassword123!"
  message_action     = "SUPPRESS" 
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.client.id
}