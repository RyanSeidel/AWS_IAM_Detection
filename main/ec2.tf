# 1. S3 BUCKET & DYNAMIC CODE UPLOAD
resource "aws_s3_bucket" "dashboard_code" {
  bucket_prefix = "insiderwatch-code-"
  force_destroy = true
}

resource "aws_s3_object" "dashboard_py" {
  bucket = aws_s3_bucket.dashboard_code.id
  key    = "dashboard.py"
  
  # Reads the local Python file and injects the Cognito Client ID
  content = templatefile("${path.module}/../ec2/dashboard.py", {
    client_id = aws_cognito_user_pool_client.client.id
  })

  etag = md5(templatefile("${path.module}/../ec2/dashboard.py", {
    client_id = aws_cognito_user_pool_client.client.id
  }))
}

# 2. IAM ROLE & INSTANCE PROFILE
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
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.dashboard_code.arn,
          "${aws_s3_bucket.dashboard_code.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "dashboard_profile" {
  name = "insider-threat-dashboard-profile"
  role = aws_iam_role.dashboard_role.name
}

# 3. EC2 SECURITY GROUP (Public Access, protected by app-level login)
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

# 4. AMAZON EC2 INSTANCE
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "dashboard" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.dashboard_profile.name
  vpc_security_group_ids = [aws_security_group.dashboard_sg.id]

  user_data_replace_on_change = true

  user_data = <<-BASH
              #!/bin/bash
              dnf update -y
              dnf install -y python3 python3-pip

              # 1. Download the code FIRST using the intact system AWS CLI
              aws s3 cp s3://${aws_s3_bucket.dashboard_code.id}/dashboard.py /home/ec2-user/dashboard.py
              chown ec2-user:ec2-user /home/ec2-user/dashboard.py

              # 2. Switch to ec2-user, create a virtual environment, and start the app
              su - ec2-user -c "
                python3 -m venv /home/ec2-user/venv
                source /home/ec2-user/venv/bin/activate
                
                pip install streamlit pandas boto3 streamlit-cookies-controller
                
                export AWS_DEFAULT_REGION=us-east-1
                
                nohup python3 -m streamlit run /home/ec2-user/dashboard.py > /home/ec2-user/streamlit.log 2>&1 &
              "
              BASH

  tags = {
    Name = "InsiderWatch-Dashboard"
  }

  # Forces Terraform to wait for the IAM policy and file upload to finish before booting
  depends_on = [
    aws_s3_object.dashboard_py,
    aws_iam_role_policy.dashboard_policy
  ] 
}

output "dashboard_url" {
  value = "http://${aws_instance.dashboard.public_ip}:8501"
}