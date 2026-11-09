variable "enable_alb_asg" {
  description = "Toggle for High Availability (ALB + ASG)"
  type        = bool
  default     = false
}

# Fetch default VPC and Subnets to place the Load Balancer
data "aws_vpc" "default" { default = true }
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# 1. ALB Security Group (Public Web Traffic)
resource "aws_security_group" "alb_sg" {
  count       = var.enable_alb_asg ? 1 : 0
  name        = "insider-threat-alb-sg"
  description = "Allow HTTP traffic to ALB"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 80
    to_port     = 80
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

# 2. Application Load Balancer
resource "aws_lb" "dashboard_alb" {
  count              = var.enable_alb_asg ? 1 : 0
  name               = "insider-threat-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg[0].id]
  subnets            = data.aws_subnets.default.ids
}

# 3. Target Group (Pings Streamlit's built-in health check)
resource "aws_lb_target_group" "dashboard_tg" {
  count    = var.enable_alb_asg ? 1 : 0
  name     = "insider-threat-tg"
  port     = 8501
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id
  
  health_check {
    path                = "/_stcore/health"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "http" {
  count             = var.enable_alb_asg ? 1 : 0
  load_balancer_arn = aws_lb.dashboard_alb[0].arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dashboard_tg[0].arn
  }
}

# 4. EC2 Launch Template (Instructions for the ASG)
resource "aws_launch_template" "dashboard_lt" {
  count         = var.enable_alb_asg ? 1 : 0
  name_prefix   = "insider-threat-lt-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  iam_instance_profile {
    name = aws_iam_instance_profile.dashboard_profile.name
  }

  vpc_security_group_ids = [aws_security_group.dashboard_sg.id]

  user_data = base64encode(<<-BASH
              #!/bin/bash
              dnf install -y docker
              systemctl start docker
              systemctl enable docker

              docker run -d \
                -p 8501:8501 \
                -e COGNITO_CLIENT_ID="${aws_cognito_user_pool_client.client.id}" \
                --restart always \
                shadab998/insiderwatch:latest
              BASH
  )
}

# 5. Auto Scaling Group
resource "aws_autoscaling_group" "dashboard_asg" {
  count               = var.enable_alb_asg ? 1 : 0
  name                = "insider-threat-asg"
  desired_capacity    = 1
  max_size            = 2
  min_size            = 1
  vpc_zone_identifier = data.aws_subnets.default.ids
  target_group_arns   = [aws_lb_target_group.dashboard_tg[0].arn]

  launch_template {
    id      = aws_launch_template.dashboard_lt[0].id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "InsiderWatch-Dashboard-ASG"
    propagate_at_launch = true
  }
  
  depends_on = [
    aws_iam_role_policy.dashboard_policy
  ]
}