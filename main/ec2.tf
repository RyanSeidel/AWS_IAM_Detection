# 1. IAM ROLE & INSTANCE PROFILE
resource "aws_iam_role" "dashboard_role" {
  name = "insider-threat-dashboard-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "dashboard_policy" {
  name = "insider-threat-dashboard-policy"
  role = aws_iam_role.dashboard_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["dynamodb:Scan", "dynamodb:Query"]
        # Wildcard account IDs to prevent ARN mismatches causing AccessDenied
        Resource = [
          "arn:aws:dynamodb:us-east-1:*:table/insider-threat-alerts",
          "arn:aws:dynamodb:us-east-1:*:table/insider-threat-baseline"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "dashboard_profile" {
  name = "insider-threat-dashboard-profile"
  role = aws_iam_role.dashboard_role.name
}

# 2. EC2 SECURITY GROUP (Public Access, protected by app-level login)
resource "aws_security_group" "dashboard_sg" {
  name        = "insider-threat-dashboard-sg"
  description = "Security group for Streamlit dashboard"

  ingress {
    description = "Streamlit UI - Public"
    from_port   = 8501
    to_port     = 8501
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  ingress {
    description = "SSH Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. AMAZON EC2 INSTANCE
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "dashboard" {
  count                  = var.enable_alb_asg ? 0 : 1
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.dashboard_profile.name
  vpc_security_group_ids = [aws_security_group.dashboard_sg.id]

  user_data_replace_on_change = true

  user_data = <<-BASH
              #!/bin/bash
              dnf install -y docker
              systemctl start docker
              systemctl enable docker

              # Pass the Cognito Client ID from Terraform into the container
              docker run -d \
                -p 8501:8501 \
                -e COGNITO_CLIENT_ID="${aws_cognito_user_pool_client.client.id}" \
                --restart always \
                shadab998/insiderwatch:latest
              BASH

  tags = {
    Name = "InsiderWatch-Dashboard"
  }

  # Forces Terraform to wait for the IAM policy to finish before booting
  depends_on = [
    aws_iam_role_policy.dashboard_policy
  ] 
}

output "dashboard_url" {
  value = var.enable_alb_asg ? "http://${aws_lb.dashboard_alb[0].dns_name}" : "http://${aws_instance.dashboard[0].public_ip}:8501"
  description = "The URL to access the InsiderWatch Dashboard"
}